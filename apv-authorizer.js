const crypto = require('crypto');
const axios = require('axios');
var { rsaPublicKeyPem } = require('./generatePublicKey');



let isValidSignature = (token) => {
    return new Promise(async (resolve, reject) => {
        let jwtToken = await decodeToken(token);
        if (!jwtToken || !jwtToken.jwtTokenHeader || !jwtToken.jwtTokenHeader.kid) {
            resolve(false);
        }

        await verifySignature(jwtToken.jwtTokenHeader.kid, token).then(() => {
            resolve(jwtToken);
        }).catch((err) => {
            console.log(err);
            resolve(false);
        })
    })

}


let decodeToken = (token) => {
    return new Promise((resolve, reject) => {
        try {
            let split_string = token.split(".");
            let base64EncodedHeader = split_string[0];
            let base64EncodedBody = split_string[1];

            let jwtTokenHeader = Buffer.from(base64EncodedHeader, 'base64').toString('ascii')
            let jwtTokenBody = Buffer.from(base64EncodedBody, 'base64').toString('ascii')


            let jwtTokenDetails = {
                jwtTokenBody: JSON.parse(jwtTokenBody),
                jwtTokenHeader: JSON.parse(jwtTokenHeader)
            }
            resolve(jwtTokenDetails);
        } catch (err) {
            console.log(err);
            reject(err);
        }

    });
}

let verifySignature = (kid, token) => {

    return new Promise(async (resolve, reject) => {
        const env = process.env.apv_lambda_env
        let url = process.env['validate_token_url_' + env]
        await axios({
            method: 'get',
            url,
            auth: {
                username: 'the_username',
                password: 'the_password'
            }
        })
            .then(async (response) => {
                let keyObj = response.data.keys.find(x => x.kid === kid);
                let publicKey = rsaPublicKeyPem(keyObj.n, keyObj.e);
                if (!publicKey) {
                    reject("Error while generating public key");
                    return;
                }

                let signatureVerified = await isTokenValidForSignature(token, publicKey);

                if (signatureVerified) {
                    resolve(signatureVerified);
                }
                else reject("Signature not verified!");

            })
            .catch(function (error) {
                reject(error);
            });
    });
};

let isTokenValidForSignature = async (token, publicKey) => {
    if (!token) {
        console.log("The authorization token is not valid!");
        return false;
    };

    let tokenParts = token.split(".");
    if (tokenParts.length != 3) {
        console.log("The authorization token did not have 3 parts");
        return false;
    }

    try {
        let signedData = token.substring(0, token.lastIndexOf("."));
        let signatureB64u = token.substring(token.lastIndexOf(".") + 1, token.length);
        let signature = Buffer.from(signatureB64u, 'base64');

        const verify = crypto.createVerify('sha256');
        verify.update(signedData);
        verify.end();
        return (verify.verify(publicKey, signature));
    } catch (err) {
        console.log(err);
        return false
    }



};


var generatePolicy = function (principalId, effect, resource) {
    var authResponse = {};
    let method = '*';
    let method_resource = '*';
    let arnArray = resource.split(":");
    let apiGatewayArnPartials = arnArray[5].split("/");
    let region = arnArray[3];
    let awsAccountId = arnArray[4];
    let restApiId = apiGatewayArnPartials[0];
    let stage = apiGatewayArnPartials[1];

    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = `arn:aws:execute-api:${region}:${awsAccountId}:${restApiId}/${stage}/${method}/${method_resource}`;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;

    }
    return authResponse;
}

module.exports.handler = async (event) => {
    let arnData = event.methodArn;
    console.log(arnData);

    try {

        tokenPass = event.authorizationToken;
        let isValid = await isValidSignature(tokenPass);
        console.log(isValid);
        console.log("---isValid---");
        if (isValid) {
            // user is principal id 
            // id must be generated
            return generatePolicy('user', 'Allow', event.methodArn)
        } else {
            return generatePolicy('user', 'Deny', event.methodArn)

        }
    } catch (error) {
        console.log("error while authorizer")
        console.log(error)
        return generatePolicy('user', 'Deny', event.methodArn)
    }

}

// handler()