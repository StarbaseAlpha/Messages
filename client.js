'use strict';

function Messages(encryption, db, serverURL, userData = null, sock = null, push = null, options = {}) {
  let token = null;
  let serverIDK = null;
  let user = null;
  let opk = null;
  let parentChannel = '/messages';

  if (options && options.parentChannel && typeof options.parentChannel === 'string') {
    parentChannel = db.path(options.parentChannel).channel();
  }

  const REQUEST = async (method, payload) => {
    return fetch(serverURL + '/' + method, {
      "method": "POST",
      "headers": {
        "content-type": "application/json"
      },
      "body": JSON.stringify(payload)
    }).then(async response => {
      let result = await response.json();
      if (response.statusCode > 399) {
        throw (result);
        return null;
      }
      return result;
    });
  };

  const listContacts = async (query) => {
    return db.path(parentChannel).path('/contacts').list(query);
  };

  const listMessages = async (userID, query) => {
    return db.path(parentChannel).path('/contacts').path(userID).path('messages').list(query);
  };

  const resetContact = async (userID) => {
    await db.path(parentChannel).path('/contacts').path(userID).path('session').del();
    await db.path(parentChannel).path('/contacts').path(userID).path('stale').del();
    await sendMessage(userID, {
      "reset": true
    }, true).catch(err=>{return null;});
    return {
      "reset": true
    };
  };

  const clearConversation = async (userID) => {
    if (userID) {
      await db.path(parentChannel).path('/contacts').path(userID).path('messages').del();
      return true;
    } else {
      return false;
    }
  };

  const updateContact = async (userID, profile = {}, unread = false) => {
    let exists = await db.path(parentChannel).path('/contacts').path(userID).get().catch(err => {
      return null;
    });
    let updated = profile || {};
    updated.timestamp = Date.now();
    updated.unread = unread || false;
    updated.userID = userID;
    if (exists && exists.data) {
      if (!updated.name && exists.data.name) {
        updated.name = exists.data.name;
      }
      if (!updated.photo && exists.data.photo) {
        updated.photo = exists.data.photo;
      }
    }
    return db.path(parentChannel).path('/contacts').path(userID).put(updated);
  };

  const deleteContact = async (userID) => {
    await messages.resetContact(userID).catch(err=>{return null;});
    await db.path(parentChannel).path('/contacts').path(userID).del();
    return true;
  };

  const loadUser = async () => {
    if (userData) {
      user = await encryption.loadUser(userData).catch(err => {
        return null;
      });
    }
    if (!user) {
      let exists = await db.path(parentChannel).path('/user').get().catch(err => {
        return null;
      });
      if (exists) {
        user = await encryption.loadUser(exists.data);
      }
    }
    if (!user) {
      user = await encryption.createUser();
      await loadOPK();
      await sendOPK();
    } else {
      await loadOPK();
    }
    await db.path(parentChannel).path('/user').put(user.save());
    return user;
  };

  const loadOPK = async () => {
    let opkData = await db.path(parentChannel).path('/user/opk').get().catch(err => {
      return null;
    });
    if (!opkData) {
      return await updateOPK();
    }
    opk = opkData.data;
    return opkData.data;
  };

  const updateOPK = async () => {
    opk = await user.createOPK();
    await db.path(parentChannel).path('/user/opk').put(opk);
    return opk;
  };

  const getServerIDK = () => {
    return serverIDK;
  };

  const getToken = async (type) => {
    let tokenData = await db.path(parentChannel).path('/token').path(user.getID()).get().then(result => {
      return result.data;
    }).catch(err => {
      return null;
    });
    if (tokenData && tokenData.decoded && tokenData.decoded.exp > parseInt(Date.now() / 1000)) {
      serverIDK = tokenData.serverIDK;
      return tokenData[type + 'Token'];
    }
    return await hello().then(result => {
      return result[type + "Token"] || null;
    }).catch(err => {
      throw ({
        "error": "Could not obtain a token from the server."
      });
    });
  };

  const acknowledgeMessages = async (ids = []) => {
    if (!user) {
      await loadUser(userData);
    }
    let token = await getToken('user');
    if (!token) {
      return Promise.reject({
        "error": "Invalid or expired token."
      });
    }
    let sealed = await user.sealEnvelope(getServerIDK(), {
      "token": token,
      "ids": ids
    });
    let response = await REQUEST('acknowledge', sealed);
    return response;
  };

  const sendOPK = async () => {
    if (!user) {
      await loadUser(userData);
    }
    let token = await getToken('user');
    if (!token) {
      return Promise.reject({
        "error": "Invalid or expired token."
      });
    }
    let sealed = await user.sealEnvelope(getServerIDK(), {
      "opk": opk.card.opk,
      "token": token
    });
    let response = await REQUEST('opk', sealed);
    return response;
  };

  const deleteMe = async () => {
    if (!user) {
      await loadUser(userData);
    }
    let token = await getToken('user');
    if (!token) {
      return Promise.reject({
        "error": "Invalid or expired token."
      });
    }
    let sealed = await user.sealEnvelope(getServerIDK(), {
      "delete":user.getID(),
      "token":token
    });
    let response = await REQUEST('deleteme', sealed);
    await unsubscribe();
    await db.path(parentChannel).del();
    return response;
  };

  const getMessages = async (limit = 100) => {
    if (!user) {
      await loadUser(userData);
    }
    let token = await getToken('user');
    if (!token) {
      return Promise.reject({
        "error": "Invalid or expired token."
      });
    }
    let subscriptionExists = await db.path(parentChannel).path('/push').get().catch(err => {
      return null;
    });
    let sub = null;
    if (subscriptionExists) {
      sub = subscriptionExists.data.subscription.keys.auth;
    }
    let sealed = await user.sealEnvelope(getServerIDK(), {
      "token": token,
      "limit": parseInt(limit),
      "sub": sub
    });
    let response = await REQUEST('messages', sealed);
    if (!response) {
      return Promise.reject({
        "code": 400,
        "message": "Failed to open envelope."
      });
    } else {
      let msgs = [];
      let ids = [];
      for (let i = 0; i < response.data.length; i++) {
        response.data[i].data.timestamp = new Date(parseInt(response.data[i].key.slice(3, 16))).getTime();
        let msg = await readMessage(response.data[i].data, opk);
        ids.push(response.data[i].key);
        if (msg && !msg.protocol) {
          msgs.push(msg);
        }
      }
      if (ids.length) {
        await acknowledgeMessages(ids);
      }
      if (response.data.length > 0 && response.data.length < parseInt(limit) && opk.used) {
        await updateOPK();
      }
      await sendOPK();
      if (msgs.length) {
        if (gotMessagesHandler && typeof gotMessagesHandler === 'function') {
          gotMessagesHandler(true);
        }
      }
      return msgs;
    }
  };

  let saveHandler = null;
  const onSave = (cb) => {
    saveHandler = cb;
  };

  let gotMessagesHandler = null;
  const onGotMessages = (cb) => {
    gotMessagesHandler = cb;
  };

  const saveReadMessage = async (contact, message, protocol = false) => {
    let msg = {
      "to": user.getID(),
      "from": contact,
      "plaintext": message.plaintext,
      "timestamp": message.timestamp,
      "status": "received",
    };
    if (!protocol) {
      let save = await db.path(parentChannel).path('/contacts').path(contact).path('messages').path(message.timestamp).put(msg);
      if (saveHandler && typeof saveHandler === 'function') {
        saveHandler({
          "path": save.path,
          "msg": msg
        });
      }
      return msg;
    }
    if (protocol) {
      if (msg.plaintext && msg.plaintext.reset) {
        await db.path(parentChannel).path('/contacts').path(contact).path('session').del();
        await db.path(parentChannel).path('/contacts').path(contact).path('stale').del();
        return null;
      }
      return null;
    }
  };

  const readMessage = async (env) => {
    let saved = null;
    let opened = await user.openEnvelope(env);
    if (opened.plaintext && opened.plaintext.init && opened.plaintext.init.from && opened.from !== opened.plaintext.init.from) {
      return null;
    }
    let userExists = await db.path(parentChannel).path('/contacts').path(opened.from).get().catch(err => {
      return null;
    });
    if (userExists && userExists.data.blocked) {
      return null;
    }
    let exists = await db.path(parentChannel).path('/contacts').path(opened.from).path('session').get().catch(err => {
      return null;
    });
    if (exists) {
      let session = await user.loadSession(exists.data);
      let read = await session.read(opened.plaintext).catch(err => {
        return null;
      });
      if (read) {
        read.timestamp = env.timestamp;
        saved = await saveReadMessage(opened.from, read, env.protocol || false);
        if (!env.protocol) {
          await db.path(parentChannel).path('/contacts').path(opened.from).path('session').put(session.save());
        }
      } else {
        if (opened.plaintext.init) {
          if (!env.protocol) {
            await db.path(parentChannel).path('/contacts').path(opened.from).path('stale').put(session.save());
          }
          session = await user.openSession(opened.plaintext.init, opk.secret);
          opk.used = true;
        } else {
          let stale = await db.path(parentChannel).path('/contacts').path(opened.from).path('stale').get().catch(err => {
            return null;
          });
          if (stale) {
            if (!env.protocol) {
              await db.path(parentChannel).path('/contacts').path(opened.from).path('stale').put(session.save());
            }
            session = await user.loadSession(stale.data);
          }
        }
        read = await session.read(opened.plaintext).catch(err => {
          return null;
        });
        if (read) {
          read.timestamp = env.timestamp;
          saved = await saveReadMessage(opened.from, read, env.protocol || false);
          if (!env.protocol) {
            await db.path(parentChannel).path('/contacts').path(opened.from).path('session').put(session.save());
          }
        }
      }
      return saved;
    } else {
      let session = null;
      if (!opened.plaintext.init) {
        let stale = await db.path(parentChannel).path('/contacts').path(opened.from).path('stale').get().catch(err => {
          return null;
        });
        if (!stale) {
          await resetContact(opened.from).catch(err=>{return null;});
          return null;
        }
        session = await user.loadSession(stale.data);
      } else {
        session = await user.openSession(opened.plaintext.init, opk.secret);
        opk.used = true;
      }
      let read = await session.read(opened.plaintext).catch(err => {
        return null;
      });
      if (read) {
        read.timestamp = env.timestamp;
        saved = await saveReadMessage(opened.from, read, env.protocol || false);
        if (!env.protocol) {
          await db.path(parentChannel).path('/contacts').path(opened.from).path('session').put(session.save());
        }
      } else {
        await resetContact(opened.from).catch(err=>{return null;});
      }
      return saved;
    }
  };

  const getID = () => {
    return user.getID();
  };

  const sendMessage = async (to, msg, protocol = false) => {
    if (!user) {
      await loadUser(userData);
    }

    let token = await getToken('anon');

    let exists = await db.path(parentChannel).path('/contacts').path(to).path('session').get().catch(err => {
      return null;
    });
    let session = null;
    if (exists) {
      session = await user.loadSession(exists.data);
    } else {
      let card = await getCard(to);
      session = await user.createSession(card);
      await db.path(parentChannel).path('/contacts').path(to).path('session').put(session.save());
    }
    let send = await session.send(msg);
    let sealed = await user.sealEnvelope(to, send);
    if (protocol) {
      sealed.protocol = true;
    }

    let sent = await REQUEST('send', {
      token,
      "msg": sealed
    }).catch(err => {
      return null;
    });
    if (sent) {
      await db.path(parentChannel).path('/contacts').path(to).path('session').put(session.save());
      if (!protocol) {
        await db.path(parentChannel).path('/contacts').path(to).path('messages').path(sent.timestamp).put({
          "to": to,
          "from": user.getID(),
          "plaintext": msg,
          "timestamp": sent.timestamp,
          "status": "sent"
        });
      }
      return Promise.resolve(sent);
    } else {
      return Promise.reject({
        "code": 400,
        "message": "Failed to send message!"
      });
    }
  };

  const getCard = async (id) => {
    if (!user) {
      await loadUser(userData);
    }

    let token = await getToken('anon');
    return REQUEST('card', {
      "token": token,
      "msg": {
        "id": id
      }
    }).catch(err => {
      return null;
    });
  };

  const connect = async () => {
    if (sock) {
      sock.onState(async (s) => {
        if (s === 'connected') {
          sock.send({
            "id": user.getID(),
            "token": await getToken('user')
          });
        }
      });
      sock.onMessage(async () => {
        await getMessages()
      });
      if (!sock.getState()) {
        sock.connect();
      }
    }
  };

  const hello = async () => {
    if (!user) {
      await loadUser(userData);
    }
    let opk = await user.createOPK();
    let response = await REQUEST('hello', opk.card);
    let opened = await user.openEnvelope(response);
    let userToken = opened.plaintext.userToken;
    let anonToken = opened.plaintext.anonToken;
    let decoded = JSON.parse(cryptic.toText(cryptic.decode(userToken.split('.')[1])));
    serverIDK = opened.from;
    await db.path(parentChannel).path('/token').path(user.getID()).put({
      "anonToken": anonToken,
      "userToken": userToken,
      "decoded": decoded,
      "serverIDK": opened.from
    });
    return {
      anonToken,
      userToken,
      decoded
    };
  };

  const subscribe = async (e) => {
    if (!push) {
      return {
        "supported": false
      };
    }
    const allowed = push.getPermission().then(result => {
      return (result === 'granted');
    }).catch(err => {
      return false;
    });
    if (!allowed) {
      return null;
    }
    return await push.subscribe(serverURL + '/push/subscribe').then(async result => {
      return await db.path(parentChannel).path('/push').put({
        subscription: result.subscription
      }).then(saved => {
        return {
          "subscribed": true
        };
      });
    });
  };

  const unsubscribe = async (e) => {
    if (!push) {
      return {
        "supported": false
      };
    }
    return await push.unsubscribe(serverURL + '/push/unsubscribe').then(async result => {
      return await db.path(parentChannel).path('/push').del().then(deleted => {
        return {
          "unsubscribed": true
        };
      });
    });
  };

  const getContact = async (userID) => {
    return await db.path(parentChannel).path('/contacts').path(userID).get().then(result => {
      return result.data;
    }).catch(err => {
      return null
    });
  };

  const isSubscribed = async () => {
    return await db.path(parentChannel).path('/push').get().then(result => {
      return true
    }).catch(err => {
      return false;
    });
  };

  return {
    getMessages,
    sendMessage,
    getID,
    getToken,
    listContacts,
    updateContact,
    resetContact,
    deleteContact,
    listMessages,
    clearConversation,
    deleteMe,
    onSave,
    connect,
    subscribe,
    unsubscribe,
    getContact,
    isSubscribed,
    onGotMessages,
    "db":db
  };

}
