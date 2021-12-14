'use strict';

const express = require('express');
const router = express.Router();

function Messages(encryption, db, push=null, options={}) {

  let server = {};
  let iss;
  let serverUser;
  let secret;
  let liveUsers = {};
  let onSend = null;
  let parentChannel = "/messages";

  if (options && options.parentChannel && typeof options.parentChannel === 'string') {
    parentChannel = db.path(options.parentChannel).channel();
  }

  const cryptic = encryption.cryptic;

  const sendHandler = (cb) => {
    onSend = cb;
  };

  const Load = async () => {
    if (serverUser && secret && iss) {
      return true;
    }
    let exists = await db.path(parentChannel).path('serverUser').get().catch(err=>{return null;});
    if (exists) {
      serverUser = await encryption.loadUser(exists.data.user);
      secret = exists.data.secret;
    } else {
      serverUser = await encryption.createUser();
      secret = cryptic.encode(cryptic.random(32));
      await db.path(parentChannel).path('serverUser').put({"user":serverUser.save(), "secret":secret});
    }
    if (!iss) {
      iss = serverUser.getID();
    }
    return true;
  };

  const createToken = async (sub, exp = (1000 * 60 * 30)) => {
    let header = {
      "typ": "JWT",
      "alg": "HS256"
    };
    let payload = {
      "sub": sub,
      "iss": iss,
      "iat": parseInt(Date.now() / 1000),
      "exp": parseInt((Date.now() + exp) / 1000)
    };
    let token = cryptic.encode(cryptic.fromText(JSON.stringify(header))) + '.' + cryptic.encode(cryptic.fromText(JSON.stringify(payload)));
    let sig = await cryptic.hmacSign(cryptic.fromText(secret), cryptic.fromText(token));
    return token + '.' + sig;
  };

  const validateToken = async (token="", subject="") => {
    await Load();
    try {
    let parts = token.split('.');
    if (!parts || parts.length < 3) {
      return false;
    }
    let payload = JSON.parse(cryptic.toText(cryptic.decode(parts[1])));
    let sig = token.split('.').slice(2).join('');
    let hmac = await cryptic.hmacVerify(cryptic.fromText(secret), sig, cryptic.fromText(token.split('.').slice(0,2).join('.')));
    return (subject === payload.sub && hmac && payload.exp >= parseInt(Date.now() / 1000) && payload.iat <= parseInt(Date.now() / 1000));
    } catch (err) {
      return false;
    };
  };

  const open = async (sealed) => {
    let opened = await serverUser.openEnvelope(sealed);
    return opened;
  };

  const hello = async (card = {}) => {
    let userToken = await createToken(card.user || "");
    let anonToken = await createToken("ANONYMOUS");
    let payload = {
      "anonToken": anonToken,
      "userToken": userToken
    };
    let sealed = await serverUser.sealEnvelope(card.user||"", payload).catch(err=>{console.log(err);return null;});
console.log(sealed);
    return sealed;
  };

  const subscribe = async ({subscription, token}) => {
    await db.path(parentChannel).path('push').path(subscription.keys.auth).put(subscription);
    return true;
  };

  const unsubscribe = async ({subscription, token}) => {
    if (subscription && subscription.auth) {
      await db.path(parentChannel).path('push').path(subscription.auth).del();
    }
    return true;
  };

  if (push) {
    push.onSubscribe(subscribe);
    push.onUnsubscribe(unsubscribe);
  }

  const addClient = async (client) => {
    await Load();
    client.on('error', (e)=>{return null;});
    client.on('message', async (message) => {
      let m = {};
      try {
        m = JSON.parse(message);
      } catch(err) {
      }
      if (m.token && m.id) {
        let valid = await validateToken(m.token, m.id).catch(err=>{return null});
        if (valid) {
          client.auth = m.id;
          if (!liveUsers[m.id]) {
            liveUsers[m.id] = {};
          }
          liveUsers[m.id][client.id] = client;
        } else {
          client.close();
        }
      } else {
        client.close();
      }
    });
    client.on('close', async () => {
      if (client.auth) {
        delete liveUsers[client.auth][client.id];
        if (!Object.keys(liveUsers[client.auth]).length) {
          delete liveUsers[client.auth];
        }
      }
    });
  };

  const sockSend = (m) => {
    if (m.to && liveUsers[m.to]) {
      for(let u in liveUsers[m.to]) {
        liveUsers[m.to][u].send(1);
      }
    }
  }

  if (push) {
    router.use('/push', push.express());
  }

  router.use('/opk', async (req, res) => {
    await Load();
    let env = req.body || {};
    open(env).then(async result=>{
      let userID = result.from;
      let opk = result.plaintext.opk || null;
      let token = result.plaintext.token || null;
      let valid = await validateToken(token, userID);
      if (!valid) {
        return res.status(400).json({"code":400, "message":"Token is expired or invalid."});
      }
      await db.path(parentChannel).path('users').path(userID).path('opk').put({"user":userID, opk});
      res.json({"updated":true});
    }).catch(err=>{
      res.status(400).json({"code":400,"message":"Server could not read request!"});
    });
  });

  router.use('/messages', async (req, res) => {
    await Load();
    let env = req.body || {};
    await open(env).then(async result=>{
      let userID = result.from;
      let msg = result.plaintext;
      let limit = 100;
      if (msg.limit && typeof msg.limit === 'number' && parseInt(msg.limit) <= 100 && parseInt(msg.limit) > 0) {
        limit = parseInt(msg.limit);
      }
      let valid = await validateToken(msg.token||null, userID);
      if (!valid) {
        return res.status(400).json({"code":400, "message":"Token is expired or invalid."});
      }
      let sub = false;
      if (msg.sub) {
        sub = msg.sub;
      }
      let profileKey = null;
      if (msg.profileKey) {
        profileKey = msg.profileKey;
      }
      let messages = await db.path(parentChannel).path('users').path(userID).path('messages').list({"values":true, "limit":limit});
      let saved = await db.path(parentChannel).path('users').path(userID).put({"user":userID, "timestamp":Date.now(), "sub":sub, "profileKey":profileKey});
      res.json(messages);
    }).catch(err=>{
      res.status(400).json({"code":400,"message":"Server could not read request!"});  
    });
  });

  router.use('/acknowledge', async (req, res) => {
    await Load();
    let env = req.body || {};
    let result = await open(env).catch(err=>{});
    if (!result) {
      res.status(400).json({"code":400,"message":"Server could not read request!"});
    }
    let userID = result.from;
    let body = result.plaintext || {};
    let ids = body.ids || [];
    let valid = await validateToken(body.token||null, userID);
    if (!valid) {
      return res.status(400).json({"code":400, "message":"Token is expired or invalid."});
    }
    let items = ids.map(val=>{
      return db.path(parentChannel).path('users').path(userID).path('messages').path(val).parse().dsPath;
    });
    await db.datastore.del(items);
    res.json({"deleted":true});
  });

  router.use('/send', async (req, res) => {
    await Load();
    let body = req.body || {};
    let msg = body.msg || {};
    let valid = await validateToken(body.token||null, 'ANONYMOUS');
    if (!valid) {
      return res.status(400).json({"code":400, "message":"Token is expired or invalid."});
    }
    let inbox = await db.path(parentChannel).path('users').path(msg.to).get().catch(err=>{return null;});
    if (!inbox) {
      return res.status(404).json({"code":404, "message":"User not found."});
    }
    let timestamp = Date.now();
    let id = ('000' + timestamp.toString() + cryptic.toHex(cryptic.random(16)).slice(0,32));
    let idc = ('000' + timestamp.toString() + cryptic.toHex(cryptic.random(16)).slice(0,32));
    await db.path(parentChannel).path('users').path(msg.to).path('messages').path(id).put(msg);
    await db.path(parentChannel).path('count').path(idc).put({"timestamp":timestamp});
    if (onSend && typeof onSend === 'function') {
      onSend({"to":msg.to, "timestamp":timestamp});
    }
    if (inbox.data.sub && push && typeof push.send === 'function') {
      let sub = await db.path(parentChannel).path('push').path(inbox.data.sub).get().catch(err=>{return null;});
      if (sub) {
        push.send(sub.data, {"title":"New Secure Message!", "body":"You have unread messages.", "badge":"https://www.themike.org/icons/notify-icon.png", "data":{"url":"/messages"}});
      }
    }
    sockSend({"to":msg.to, "timestamp":timestamp});
    res.json({"sent":true, "timestamp":timestamp});
  });

  router.use('/card', async (req, res) => {
    await Load();
    let body = req.body || {};
    let msg = body.msg || {};
    let valid = await validateToken(body.token||null, 'ANONYMOUS');
    if (!valid) {
      return res.status(400).json({"code":400, "message":"Token is expired or invalid."});
    }
    let exists = await db.path(parentChannel).path('users').path(msg.id).path('opk').get().catch(err=>{return null;});
    if (!exists) {
      return res.status(404).json({"code":404, "message":"User not found."});
    }
    res.json({
      "user":exists.data.user||null,
      "opk":exists.data.opk||null
    });
  });

  router.use('/hello', async (req, res) => {
    await Load();
    hello(req.body||{}).then(result => {
      res.json(result);
    }).catch(err => {
      res.status(400).json({"code":400,"message":"Server could not say hello!"});
    });
  });

  router.use(async (err, req, res, next) => {
    res.status(400).json({"code":400, "message":err.message||err.toString()||"Error!"});
  });

  server.addClient = addClient;
  server.validateToken = validateToken;
  server.onSend = sendHandler;
  server.express = () => {
    return router;
  };

  return server;
}

module.exports = Messages;
