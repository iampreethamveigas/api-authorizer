// handler.spec.ts
//import * as mocha from 'mocha';
import * as chai from 'chai';;

const index = require('../src/ive-authorizer.js')

const expect = chai.expect;

describe("handler ive_datamart_crawler", () => {
    describe("ive_datamart_crawler test", () => {
        it("should return Serverless boilerplate message", () => {
            index.handler(null, null, (error: Error, result: any) => {
                console.log(result.body, 'body')
                expect(error).to.be.null;
            })
        });
    });
});