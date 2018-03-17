var async = require('async');
var crypto = require('crypto');
var mongoose = require('mongoose');
var utils = module.parent.require('./utils');
var Password = module.parent.require('./password');
var user = module.parent.require('./user');
var db = module.parent.require('./database');
var translator = module.parent.require('./translator');
mongoose.connect('mongodb://nodebb:12345678@127.0.0.1:27017/nodebb');
var passport = module.parent.require('passport'),
    passportLocal = module.parent.require('passport-local').Strategy,
    plugin = {};
var Schema = mongoose.Schema;
var UserSchema = new Schema({
    username: String,
    uid: Number
});
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
                    host: 'yuxin.dian.org.cn',
                    path: '/bbslogin',
                    port: '80',
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
                            // winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));
                            next(new Error('[[error:invalid-username-or-password]]'));
                        }
                        else if (iconv.decode(bufferHelper.toBuffer(), 'gb2312').indexOf('错误! 错误的使用者帐号!') > -1) {
                            winston.info('Dian user not found');
                            // winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));
                            next(new Error('[[error:invalid-username-or-password]]'));
                        } else {
                            winston.info('Dian user found');
                            // winston.info(iconv.decode(bufferHelper.toBuffer(), 'gb2312'));

                            var userData = {
                                username: username,
                                email: username + '@dian.org.cn',
                                password: password
                            };
                            user.create(userData, function (err) {
                                var Users = module.parent.require('./user');
                                Users.getUidByUsername(username, function (err, uid) {
                                    // winston.info(username);
                                    // winston.info(uid);
                                    newuid = uid;
                                    // winston.info(newuid);
                                    // winston.info('is uid');
                                    next(null, {
                                        uid: newuid
                                    }, '[[success:authentication-successful]]');
                                });
                            });
                        }
                    })
                })
                // console.log(postData);
                request.write(postData);
                request.end();
            } else {
                var userslug = utils.slugify(username);
                var uid;
                var userData = {};
                if (!password || !utils.isPasswordValid(password)) {
                    return next(new Error('[[error:invalid-password]]'));
                }

                if (password.length > 4096) {
                    return next(new Error('[[error:password-too-long]]'));
                }
                // winston.info('doc');
                // winston.info(doc);
                async.waterfall([
                    function (next) {
                        user.getUidByUserslug(userslug, next);
                    },
                    function (_uid, next) {
                        uid = _uid;
                        // winston.info('uid');
                        // winston.info(uid);
                        // winston.info('123');
                        async.parallel({
                            userData: function (next) {
                                db.getObjectFields('user:' + uid, ['password', 'passwordExpiry'], next);
                            },
                            isAdmin: function (next) {
                                user.isAdministrator(uid, next);
                            },
                            banned: function (next) {
                                user.isBanned(uid, next);
                            },
                        }, next);
                    },
                    function (result, next) {
                        userData = result.userData;
                        // winston.info('userData');
                        // winston.info(userData);
                        userData.uid = uid;
                        userData.isAdmin = result.isAdmin;
                        if (result.banned) {
                            return getBanInfo(uid, next);
                        }
                        // winston.info('ready for Comparing');
                        // winston.info('Comparing');
                        Password.compare(password, userData.password, next);
                        // winston.info('Compare finished');
                    },
                    function (passwordMatch, next) {
                        // winston.info('passwordMatch');
                        // winston.info(passwordMatch);
                        if (!passwordMatch) {
                            return next(new Error('[[error:invalid-login-credentials]]'));
                        }
                        user.auth.clearLoginAttempts(uid);
                        next(null, {
                            uid: uid
                        }, '[[success:authentication-successful]]');
                        // winston.info('next');
                    },
                ], next);
                // newuid = doc.uid;
                // winston.info(newuid);
                // winston.info('is uid');
                // next(null, {
                //     uid: newuid
                // }, '[[success:authentication-successful]]');
            }
        });
};

function getBanInfo(uid, callback) {
	var banInfo;
	async.waterfall([
		function (next) {
			user.getLatestBanInfo(uid, next);
		},
		function (_banInfo, next) {
			banInfo = _banInfo;
			if (banInfo.reason) {
				return next();
			}

			translator.translate('[[user:info.banned-no-reason]]', function (translated) {
				banInfo.reason = translated;
				next();
			});
		},
		function (next) {
			next(new Error(banInfo.expiry ? '[[error:user-banned-reason-until, ' + banInfo.expiry_readable + ', ' + banInfo.reason + ']]' : '[[error:user-banned-reason, ' + banInfo.reason + ']]'));
		},
	], function (err) {
		if (err) {
			if (err.message === 'no-ban-info') {
				err.message = '[[error:user-banned]]';
			}
		}
		callback(err);
	});
}



module.exports = plugin;