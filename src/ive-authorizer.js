const crypto = require('crypto');
const axios = require('axios');
var { rsaPublicKeyPem } = require('./generatePublicKey');
const AWS = require('aws-sdk');
AWS.config.logger = console;
let tokenPass = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IllNRUxIVDBndmIwbXhvU0RvWWZvbWpxZmpZVSIsImtpZCI6IllNRUxIVDBndmIwbXhvU0RvWWZvbWpxZmpZVSJ9.eyJhdWQiOiJlNjdlNzNhNC00NTAwLTQwMzAtYTkwZS02MmYzN2JmZTI3OGYiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC85MTA3YjcyOC0yMTY2LTRlNWQtOGQxMy1kMWZmZGYwMzUxZWYvIiwiaWF0IjoxNTg0NTE1ODQ1LCJuYmYiOjE1ODQ1MTU4NDUsImV4cCI6MTU4NDUxOTc0NSwiYWlvIjoiQVNRQTIvOE9BQUFBS3A5V0NGM2NRVnJ0VktKK0dYdkJKSHFlV3VmN2d1bnNlNjFUODl6YjBPYz0iLCJhbXIiOlsicHdkIl0sImZhbWlseV9uYW1lIjoiU2FqamFuYXB1IiwiZ2l2ZW5fbmFtZSI6IlZlbmthdGVzaCIsImhhc2dyb3VwcyI6InRydWUiLCJpcGFkZHIiOiI0My4yNDcuMTU3LjIiLCJuYW1lIjoiNDM4NDQ4Iiwibm9uY2UiOiJjZGE3MmRjZC1mOTRmLTQwYzctYWYxMS00ZDg5MDA0MDg2MTUiLCJvaWQiOiI1MDNhMGE2NC1iMmIxLTRmN2UtYmU2ZC04OTZjMjlhNjcwMWQiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtMTc3MjU2NDAxOC0yMTc5NjYwMzc4LTMyNjk3OTU5MTEtMjE1MDYyIiwicm9sZXMiOlsiSVZFLUJ1c2luZXNzQWRtaW4iXSwic3ViIjoiYnFCdmU1Zk5GelFCUmtkZjhjdTlWQ18zcDRiXzVKN1NTbS1ZcFY0TGFhZyIsInRpZCI6IjkxMDdiNzI4LTIxNjYtNGU1ZC04ZDEzLWQxZmZkZjAzNTFlZiIsInVuaXF1ZV9uYW1lIjoiVmVua2F0ZXNoLlNhamphbmFwdUB0bW5hdGVzdC5jb20iLCJ1cG4iOiJWZW5rYXRlc2guU2FqamFuYXB1QHRtbmF0ZXN0LmNvbSIsInV0aSI6IjJqblJLUERpNWtHYXlBWHEzV0pBQVEiLCJ2ZXIiOiIxLjAiLCJ3b3JrZGF5SWQiOiI0Mzg0NDgifQ.EYvTbX9ssCGmjLDX7hGikcom8rMzcxsgu35bIro7iEO_Fb-ROUKh99Zn87u1fkAD97pfnqUeNejdphWESCgaKUkSupYnjFMUjCF13c2BiSnDWLMM7vjYqfvOvcxAOFzXeJEp5YCOR7M8Boxg2PzT5_XO1YFlPeNTl-l9bLeMRk6LoWXHl2Y-JE7s6ZKqjJPAiw0EZmPJfkL5xCR6GGQEdY3kwcEA3JFQ1W_KWagQ5LjRIIZYPHsspI7HLCUFYg-d3csTWe7YLASyv1SNzEJ0QawnK6nFcq1e0CvsalsR-JFqVvqREQtMBzZEDNDJuDR7r6Hd_EU_qytMD90KzJgqvA'



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
        const env = process.env.ive_lambda_env
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
    event['methodArn'] = arnData
    try {

        // let tokenPass = event.authorizationToken;
        let isValid = await isValidSignature(tokenPass);
        console.log(isValid);
        console.log("---isValid---");
        if (isValid) {
            // user is principal id 
            // id must be generated
            return generatePolicy('user', 'Allow', arnData, event.methodArn)
        } else {
            return generatePolicy('user', 'Deny', arnData, event.methodArn)

        }
    } catch (error) {
        console.log("error while authorizer")
        console.log(error)
        return generatePolicy('user', 'Deny', event.methodArn)
    }

}

// handler()