var async = require('async');
var crypto = require('crypto');
var mongoose = require('mongoose');
mongoose.connect('mongodb://nodebb:12345678@127.0.0.1:27017/nodebb');
var passport = module.parent.require('passport'),
    passportLocal = module.parent.require('passport-local').Strategy,
    plugin = {};
var Schema = mongoose.Schema;
var UserSchema = new Schema({
    username: String,
    uid: Number
});
// var plugins = module.parent.require('../plugins');
var User = mongoose.model('User', UserSchema, 'objects');
var http = require('http');
var iconv = require('iconv-lite');
var BufferHelper = require('bufferhelper');
var querystring = require('querystring');
winston = module.parent.require('winston');
function hashPW(pwd) {
    return crypto.createHash('sha256').update(pwd).
        digest('base64').toString();
}
// passport.use(new passportLocal({ passReqToCallback: true }, plugin.continueLogin));

plugin.login = function () {
    winston.info('[login] Registering new local login strategy');
    passport.use(new passportLocal({ passReqToCallback: true }, plugin.continueLogin));
};

plugin.continueLogin = function (req, username, password, next) {
    var loginsuccess = 1;
    var newuid = 12450;
    User.findOne({ username: username }).
        exec(function (err, doc) {
            if (!doc) {
                var postData = querystring.stringify({
                    id: username,
                    pw: password
                })
                var option = {
                    host: '115.156.207.252',
                    path: '/bbslogin',
                    port: '81',
                    method: 'POST',
                    headers: {
                        'Content-type': 'application/x-www-form-urlencoded',
                        'Content-Length': postData.length
                    }
                };
                var request = http.request(option, function (response) {
                    var bufferHelper = new BufferHelper();
                    response.on('data', function (chunk) {
                        bufferHelper.concat(chunk);
                    })
                    response.on('end', function () {
                        // console.log(iconv.decode(bufferHelper.toBuffer(),'gb2312'));
                        // console.log(iconv.decode(bufferHelper.toBuffer(),'gb2312').indexOf('错误! 密码错误!'));
                        if (iconv.decode(bufferHelper.toBuffer(), 'gb2312').indexOf('错误! 密码错误!') > -1) {
                            winston.info('Dian wrong password');
                            winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));
                            next(new Error('[[error:invalid-username-or-password]]'));
                        }
                        else if (iconv.decode(bufferHelper.toBuffer(), 'gb2312').indexOf('错误! 错误的使用者帐号!') > -1) {
                            winston.info('Dian user not found');
                            winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));
                            next(new Error('[[error:invalid-username-or-password]]'));
                        } else {
                            winston.info('Dian user found');
                            winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));
                            var user = module.parent.require('./user');
                            userData = {
                                username: username,
                                email: username + '@dian.org.cn',
                                password: password
                            };

                            // async.waterfall([
                            //     function (next) {
                            //         plugins.fireHook('filter:register.interstitial', {
                            //             userData: userData,
                            //             interstitials: [],
                            //         }, next);
                            //     },
                            //     function (data, next) {
                            //         // If interstitials are found, save registration attempt into session and abort
                            //         var deferRegistration = data.interstitials.length;

                            //         if (!deferRegistration) {
                            //             return next();
                            //         }
                            //         userData.register = true;
                            //         // req.session.registration = userData;
                            //     },
                            //     function (next) {
                            //         user.shouldQueueUser(req.ip, next);
                            //     },
                            //     function (queue, next) {
                            //         plugins.fireHook('filter:register.shouldQueue', { req: req, res: res, userData: userData, queue: queue }, next);
                            //     },
                            //     function (data, next) {
                            //         if (data.queue) {
                            //             addToApprovalQueue(req, userData, callback);
                            //         } else {
                            //             user.create(userData, next);
                            //         }
                            //     },
                            //     function (_uid, next) {
                            //         newuid = _uid;
                            //     }
                            // ], function (err) {
                            //     winston.info(newuid);
                            //     winston.info('is uid');
                            //     next(null, {
                            //         uid: newuid
                            //     }, '[[success:authentication-successful]]');
                            // });
                            user.create(userData, function (err) {
                                var Users = module.parent.require('./user');
                                Users.getUidByUsername(username, function (err, uid) {
                                    winston.info(username);
                                    winston.info(uid);
                                    newuid = uid;
                                    winston.info(newuid);
                                    winston.info('is uid');
                                    next(null, {
                                        uid: newuid
                                    }, '[[success:authentication-successful]]');
                                });
                            });
                            // registerAndLoginUser(req, res, userData, next);
                            // var NewUser = mongoose.model('NewUser', UserSchema, 'objects');
                            // NewUser.findOne({ username: username }).exec(function (err, doc) {
                            //     if(!doc){
                            //         winston.info('Failed to create Dian user');
                            //     } else {
                            //         winston.info('login doc');
                            //         winston.info(doc);
                            //         newuid = doc.uid;
                            //     }
                            // });
                            // user.getUidByEmail('miracle@DIAN.ORG.CN', function (err, uid) {
                            //     // (username + '@dian.org.cn').toUpperCase()
                            //     winston.info('uid');
                            //     winston.info(uid);
                            //     newuid = uid;
                            // });
                            // newuid = uidcontent;

                        }
                    })
                })
                // console.log(postData);
                request.write(postData);
                request.end();
                // if (loginsuccess == 0) {
                //     ;
                // } else {
                //     ;
                // }
            } else {
                winston.info('doc');
                winston.info(doc);
                // stringdoc = doc.join('');
                // winston.info('stringdoc');
                // winston.info(stringdoc);
                // winston.info(stringdoc.username);
                newuid = doc.uid;
                // uiddocarray = string.match(/uid\:\ \d+/g);
                // winston.info('uiddocarray');
                // winston.info(uiddocarray);
                // uiddoc = uiddocarray[0];
                // winston.info('uiddoc');
                // winston.info(uiddoc);
                // uidstring = uiddoc.match(/\d+/g)[0];
                // winston.info('uidstring');
                // winston.info(uidstring);
                // uid = Number(uidstring);
                winston.info(newuid);
                winston.info('is uid');
                next(null, {
                    uid: newuid
                }, '[[success:authentication-successful]]');
            }
        })
    // next(new Error('[[error:invalid-username-or-password]]'));
    // Do your stuff here (query API or SQL db, etc...)
    // If the login was successful:

    // But if the login was unsuccessful, pass an error back, like so:


    /*
        You'll probably want to add login in this method to determine whether a login
        refers to an existing user (in which case log in as above), or a new user, in
        which case you'd want to create the user by calling User.create. For your
        convenience, this is how you'd create a user:
    */

    /*
        Acceptable values are: username, email, password
    */
};

// plugin.register = function (req, res) {
// 	var registrationType = meta.config.registrationType || 'normal';

// 	if (registrationType === 'disabled') {
// 		return res.sendStatus(403);
// 	}

// 	var userData = req.body;

// 	async.waterfall([
// 		function (next) {
// 			if (registrationType === 'invite-only' || registrationType === 'admin-invite-only') {
// 				user.verifyInvitation(userData, next);
// 			} else {
// 				next();
// 			}
// 		},
// 		function (next) {
// 			if (!userData.email) {
// 				return next(new Error('[[error:invalid-email]]'));
// 			}

// 			if (!userData.username || userData.username.length < meta.config.minimumUsernameLength || utils.slugify(userData.username).length < meta.config.minimumUsernameLength) {
// 				return next(new Error('[[error:username-too-short]]'));
// 			}

// 			if (userData.username.length > meta.config.maximumUsernameLength) {
// 				return next(new Error('[[error:username-too-long]]'));
// 			}

// 			if (userData.password !== userData['password-confirm']) {
// 				return next(new Error('[[user:change_password_error_match]]'));
// 			}

// 			user.isPasswordValid(userData.password, next);
// 		},
// 		function (next) {
// 			res.locals.processLogin = true;	// set it to false in plugin if you wish to just register only
// 			plugins.fireHook('filter:register.check', { req: req, res: res, userData: userData }, next);
// 		},
// 		function (result, next) {
// 			registerAndLoginUser(req, res, userData, next);
// 		},
// 	], function (err, data) {
// 		if (err) {
// 			return helpers.noScriptErrors(req, res, err.message, 400);
// 		}

// 		if (data.uid && req.body.userLang) {
// 			user.setSetting(data.uid, 'userLang', req.body.userLang);
// 		}

// 		res.json(data);
// 	});
// };

// function registerAndLoginUser(req, res, userData, callback) {
// 	var uid;
// 	async.waterfall([
// 		function (next) {
// 			plugins.fireHook('filter:register.interstitial', {
// 				userData: userData,
// 				interstitials: [],
// 			}, next);
// 		},
// 		function (data, next) {
// 			// If interstitials are found, save registration attempt into session and abort
// 			var deferRegistration = data.interstitials.length;

// 			if (!deferRegistration) {
// 				return next();
// 			}
// 			userData.register = true;
// 			req.session.registration = userData;

// 			if (req.body.noscript === 'true') {
// 				return res.redirect(nconf.get('relative_path') + '/register/complete');
// 			}
// 			return res.json({ referrer: nconf.get('relative_path') + '/register/complete' });
// 		},
// 		function (next) {
// 			user.shouldQueueUser(req.ip, next);
// 		},
// 		function (queue, next) {
// 			plugins.fireHook('filter:register.shouldQueue', { req: req, res: res, userData: userData, queue: queue }, next);
// 		},
// 		function (data, next) {
// 			if (data.queue) {
// 				addToApprovalQueue(req, userData, callback);
// 			} else {
// 				user.create(userData, next);
// 			}
// 		},
// 		function (_uid, next) {
// 			uid = _uid;
// 			if (res.locals.processLogin) {
// 				authenticationController.doLogin(req, uid, next);
// 			} else {
// 				next();
// 			}
// 		},
// 		function (next) {
// 			user.deleteInvitationKey(userData.email);
// 			plugins.fireHook('filter:register.complete', { uid: uid, referrer: req.body.referrer || nconf.get('relative_path') + '/' }, next);
// 		},
// 	], callback);
// }

// function addToApprovalQueue(req, userData, callback) {
// 	async.waterfall([
// 		function (next) {
// 			userData.ip = req.ip;
// 			user.addToApprovalQueue(userData, next);
// 		},
// 		function (next) {
// 			next(null, { message: '[[register:registration-added-to-queue]]' });
// 		},
// 	], callback);
// }

// plugin.registerComplete = function (req, res, next) {
// 	// For the interstitials that respond, execute the callback with the form body
// 	plugins.fireHook('filter:register.interstitial', {
// 		userData: req.session.registration,
// 		interstitials: [],
// 	}, function (err, data) {
// 		if (err) {
// 			return next(err);
// 		}

// 		var callbacks = data.interstitials.reduce(function (memo, cur) {
// 			if (cur.hasOwnProperty('callback') && typeof cur.callback === 'function') {
// 				memo.push(async.apply(cur.callback, req.session.registration, req.body));
// 			}

// 			return memo;
// 		}, []);

// 		var done = function (err, data) {
// 			delete req.session.registration;
// 			if (!err && data && data.message) {
// 				return res.redirect(nconf.get('relative_path') + '/?register=' + encodeURIComponent(data.message));
// 			}
// 			if (req.session.returnTo) {
// 				res.redirect(req.session.returnTo);
// 			} else {
// 				res.redirect(nconf.get('relative_path') + '/');
// 			}
// 		};

// 		async.parallel(callbacks, function (err) {
// 			if (err) {
// 				req.flash('error', err.message);
// 				return res.redirect(nconf.get('relative_path') + '/register/complete');
// 			}

// 			if (req.session.registration.register === true) {
// 				res.locals.processLogin = true;
// 				registerAndLoginUser(req, res, req.session.registration, done);
// 			} else {
// 				// Clear registration data in session
// 				done();
// 			}
// 		});
// 	});
// };
// plugin.registerAbort = function (req, res) {
// 	// End the session and redirect to home
// 	req.session.destroy(function () {
// 		res.redirect(nconf.get('relative_path') + '/');
// 	});
// };


module.exports = plugin;