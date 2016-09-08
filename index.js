'use strict'

/**
 *  Oauth 1.0 Signature generator
 *  https://tools.ietf.org/html/rfc5849#section-3
 * 
 *  With Guidance From:
 *  https://dev.twitter.com/oauth/overview/creating-signatures
 */






/**
 * Utilities
 */
const crypto = require('crypto-js')
const _ = require('lodash')

//http://stackoverflow.com/questions/18251399/why-doesnt-encodeuricomponent-encode-single-quotes-apostrophes/18251730#18251730
const encode = function rfc3986EncodeURIComponent (str) {  
    return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
    	return '%' + c.charCodeAt(0).toString(16).toUpperCase(); 
    });
}






module.exports = function(consumerSecret, oauthTokenSecret, method, url, keys) {

    // method must be capitalised string
    method = method.toUpperCase()

    /**
     *
     * Oauth 1.0 Signature Base String Generator
     */


    let encodedKeys = {}

    // 1 - Percent encode every key and value that will be signed.
    _.forEach(keys, (value, key) => {
        let percentEncodedKey = encode(key)
        let percentEncodedValue = encode(value)
        encodedKeys[percentEncodedKey] = percentEncodedValue
    })

    // 2 - Sort the list of parameters alphabetically by encoded key
    // 3 - For each key/value pair:
    //      3.1 - Append the encoded key to the output string.
    //      3.2 - Append the ‘=’ character to the output string.
    //      3.3 - Append the encoded value to the output string.
    let outputString = Object.keys(encodedKeys)
                        .sort()
                        .reduce((prev, curr, i) => {
                            // 3.4 - If there are more key/value pairs remaining,
                            //       append a ‘&’ character to the output string.
                            if (i < Object.keys(encodedKeys).length - 1) {
                                return prev += `${curr}=${encodedKeys[curr]}&`    
                            }
                            return prev += `${curr}=${encodedKeys[curr]}`
                        }, '')




    // Convert the HTTP Method to uppercase and set the output string equal to this value.
    // Append the ‘&’ character to the output string.
    // Percent encode the URL and append it to the output string.
    let encodedURL = encode(url)

    // Append the ‘&’ character to the output string.
    // Percent encode the parameter string and append it to the output string.
    let signatureBaseString = method + '&' + encodedURL + '&' + encode(outputString)





    /**
     * Last Steps - Generating the Signing Key
     */


    // The signing key is the percent encoded consumer secret,
    // followed by an ampersand character ‘&’, followed by the
    // percent encoded token secret
    let signingKey = encode(consumerSecret) + '&' + encode(oauthTokenSecret)


    // base64 encoded HMAC-SHA1
    let hash = crypto.enc.Base64.stringify(crypto.HmacSHA1(signatureBaseString, signingKey))


    // finally, return the [RFC3986] Percent Encoded hash
    return encode(hash)

}