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
                        }
                    })
                })
                // console.log(postData);
                request.write(postData);
                request.end();
            } else {
                winston.info('doc');
                winston.info(doc);
                newuid = doc.uid;
                winston.info(newuid);
                winston.info('is uid');
                next(null, {
                    uid: newuid
                }, '[[success:authentication-successful]]');
            }
        })
};


module.exports = plugin;