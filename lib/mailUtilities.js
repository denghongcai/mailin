'use strict';

const logger = require('./logger');
const spf = require('spf-check');
const DKIM = require('dkim');

/* Provides high level mail utilities such as checking dkim, spf and computing
 * a spam score. */
module.exports = {
    /* @param rawEmail is the full raw mime email as a string. */
    validateDkim: function (rawEmail, callback) {
        DKIM.verify(new Buffer(rawEmail), function (err, res) {
            logger.debug(res);
            if (res && res.length > 0) {
                callback(null, res.every(function (record) {
                    return record.verified;
                }));
            }
            callback(err, false);
        });
    },

    validateSpf: function (ip, address, host, callback) {
        const validator = new spf.SPF(host, address);

        validator.check(ip).then(result => {
            logger.debug(result);

            if (result.result !== spf.Pass && result.result !== spf.Neutral && result.result !== spf.SoftFail) {
                callback(new Error(result.message), false);
                return;
            }
            callback(null, true);
        }).catch(function (err) {
            console.error(err);
            callback(err, false);
        });
    },

    /* @param rawEmail is the full raw mime email as a string. */
    computeSpamScore: function (rawEmail, callback) {
        return callback(null, 0.0);
    }
};
