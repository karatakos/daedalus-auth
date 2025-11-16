import { SSMClient, GetParametersByPathCommand, GetParameterCommand} from '@aws-sdk/client-ssm'
import { mockClient } from 'aws-sdk-client-mock';

import { SigninHandler, SigninCmd } from '../actions/commands/sign-in.command.js';
import { AccessTokenHandler, AccessTokenQuery } from '../actions/queries/access-token.query.js';

import { UserSignedInEvent } from '../events/user-signed-in.event.js';
import { UserSignInUnauthorizedEvent } from '../events/user-sign-in-unauthorized.event.js';

import { UserRepoFactory } from '../repository/user/user.repo.factory.js';

import { FederatedAccountType } from '../entities/user.js';
import { JwksParameterStoreCache } from '../util/jkws-paramstore-cache.js';

const privateKeyES256 = {
    Parameter: {
        Value: JSON.stringify({
            kty: "EC",
            d: "uSdIX_qNkEgxoeb2wrVzk4EH9BSgNzjl7CrSj-NlyNE",
            use: "sig",
            crv: "P-256",
            kid: "00JKEZszpbVmSex5qpqFeNsEXU0p9aWGZ-0u01s9UVc",
            x: "Um4HwI12l6n0fog_emlMTtRloRcvp7xPZ0iZ3EMnkxg",
            y: "510Q1wOWCGpzoLIwJ4Tj8GvWKE9P0QvbNYvX9oYQZTI",
            alg: "ES256",
            x5c: [ "-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCC5J0hf+o2QSDGh5vbC\ntXOTgQf0FKA3OOXsKtKP42XI0Q==\n-----END PRIVATE KEY-----\n" ]
        })
    }
};

const publicKeysES256 = {
    Parameters: [
    {
        Value: JSON.stringify({
            kty: "EC",
            use: "sig",
            crv: "P-256",
            kid: "00JKEZszpbVmSex5qpqFeNsEXU0p9aWGZ-0u01s9UVc",
            x: "Um4HwI12l6n0fog_emlMTtRloRcvp7xPZ0iZ3EMnkxg",
            y: "510Q1wOWCGpzoLIwJ4Tj8GvWKE9P0QvbNYvX9oYQZTI",
            alg: "ES256",
            x5c: [ "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUm4HwI12l6n0fog/emlMTtRloRcv\np7xPZ0iZ3EMnkxjnXRDXA5YIanOgsjAnhOPwa9YoT0/RC9s1i9f2hhBlMg==\n-----END PUBLIC KEY-----\n" ]
        })
    }]
}

const adrianEnabledNotExpiredJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwSktFWnN6cGJWbVNleDVxcHFGZU5zRVhVMHA5YVdHWi0wdTAxczlVVmMifQ.eyJ1c2VySWQiOiJlZTRlZDc5N2E0OTc0ZTEyOTlhZjRkNzZjNjdiZDcyZSIsInVzZXJuYW1lIjoiQWRyaWFuIiwicG9saWN5Ijp7ImNhcGFiaWxpdGllcyI6WyJhZG1pbiJdfSwic3RhdHVzIjoiRW5hYmxlZCIsImV4cCI6MjIzNjYyMTU4MX0.hjJJPzsNzWijaqeRsSW6laIybNPJ5Z5oFkZ3exUh3m4PVGMngxTVOBCELFuqZLJ8GIR2Lxe2-w8lCa2ss8ISMA";
const sarahEnabledExpiredJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwSktFWnN6cGJWbVNleDVxcHFGZU5zRVhVMHA5YVdHWi0wdTAxczlVVmMifQ.eyJ1c2VySWQiOiI5NTNmY2NmN2EyNDM0NTgwOGIwM2U0ODY4M2VlNmEzYiIsInVzZXJuYW1lIjoiU2FyYWgiLCJwb2xpY3kiOnsiY2FwYWJpbGl0aWVzIjpbXX0sInN0YXR1cyI6IkVuYWJsZWQiLCJleHAiOjE3MDg1MDAwODZ9.WtnZQ3tP6ifc3jcG5rvrJA7AoSN6zyUjbfh0tGqu0vKa8P0Y0fUE7gNdGDMvN85slZxmlgEURyHKUQbaX1bemw";
const timmyDisabledNotExpiredJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAwSktFWnN6cGJWbVNleDVxcHFGZU5zRVhVMHA5YVdHWi0wdTAxczlVVmMifQ.eyJ1c2VySWQiOiI5ZWQ3YWZhNWMwZDQ0YjgwYmIwYjVhODc1MzJhYzA4NCIsInVzZXJuYW1lIjoiVGltbXkiLCJwb2xpY3kiOnsiY2FwYWJpbGl0aWVzIjpbXX0sInN0YXR1cyI6IkRpc2FibGVkIiwiZXhwIjoxNzQwMDM2MDg2fQ.LXZpgkyl1ToncOmfv8dMoSO3bVubN9JfDpolNvJbNAhQcG-sBdAslgHYF8jNmmjB1XiOpgQkkA3NMKD4I7dm_g";

const mockedDatastore = [
        {
            PK: "US#ee4ed797a4974e1299af4d76c67bd72e",
            SK: "US#ee4ed797a4974e1299af4d76c67bd72e",
            username: "Adrian",             
            policy: '{"capabilities": ["admin"]}',
            status: "Enabled"
        },
        {
            PK: "US#9ed7afa5c0d44b80bb0b5a87532ac084",
            SK: "US#9ed7afa5c0d44b80bb0b5a87532ac084",
            username: "Timmy",            
            policy: '{"capabilities": []}',
            status: "Disabled"
        },
        {
            PK: "US#953fccf7a24345808b03e48683ee6a3b",
            SK: "US#953fccf7a24345808b03e48683ee6a3b",
            username: "Sarah",             
            policy: '{"capabilities": []}',
            status: "Enabled"
        },
        {
            PK: "US#953fccf7a24345808b03e48683ee6a3b",
            SK: "RT#" + sarahEnabledExpiredJWT     
        },
        {
            PK: "US#9ed7afa5c0d44b80bb0b5a87532ac084",
            SK: "RT#" + timmyDisabledNotExpiredJWT         
        },
        {
            PK: "US#ee4ed797a4974e1299af4d76c67bd72e",
            SK: "RT#" + adrianEnabledNotExpiredJWT          
        },
        {
            PK: "US#ee4ed797a4974e1299af4d76c67bd72e",
            SK: "FA#ST#KaratakosJP#1983",       // Steam Id
            token: "0000"                       // Steam Token (0000 allowed for dev)
        },
        {
            PK: "US#9ed7afa5c0d44b80bb0b5a87532ac084",
            SK: "FA#ST#LittleTimmy#1987",    
            token: "0000"
        },
        {
            PK: "US#953fccf7a24345808b03e48683ee6a3b",
            SK: "FA#ST#xDestinyStarzx#1986",   
            token: "0000"
        }
    ];

const ssm = new SSMClient();

// TODO: Replace this messy mock/factory with aws-sdk-client-mock
// 
const userRepo = UserRepoFactory.make(mockedDatastore);

const jwksCache = new JwksParameterStoreCache(ssm);
let ssmMock: any;

beforeEach(() => {
    ssmMock = mockClient(SSMClient);

    ssmMock.on(GetParameterCommand, {
        Name: "/daedalus-auth-cert/private/jwk",
        WithDecryption: true})
            .resolves(privateKeyES256);

    ssmMock.on(GetParametersByPathCommand, {
        Path: "/daedalus-auth-cert/public/jkw",
        WithDecryption: true})
            .resolves(publicKeysES256);
});

describe('Refreshing access token', () => {
    it('Throw error invalid token', async () => {
        const refreshTokenQry = new AccessTokenHandler(userRepo, jwksCache);
        await expect(refreshTokenQry.handle(new AccessTokenQuery("faketoken")))
            .rejects
            .toHaveProperty("message", "Unauthorized. Refresh token not found, please sign-in again.");
    });
    
    it('Throw error expired token', async () => {
        const refreshTokenQry = new AccessTokenHandler(userRepo, jwksCache);
        await expect(refreshTokenQry.handle(new AccessTokenQuery(sarahEnabledExpiredJWT)))
            .rejects
            .toEqual("Token invalid.");
    });

    it('Throw error disabled user', async () => {
        const refreshTokenQry = new AccessTokenHandler(userRepo, jwksCache);
        await expect(refreshTokenQry.handle(new AccessTokenQuery(timmyDisabledNotExpiredJWT)))
            .rejects
            .toHaveProperty("message", "Unauthorized. This account is disabled.");
    });

    it('Succeed for valid token', async () => {
        const refreshTokenQry = new AccessTokenHandler(userRepo, jwksCache);
        const token = await refreshTokenQry.handle(new AccessTokenQuery(adrianEnabledNotExpiredJWT));

        expect(token).toBeDefined();
    });
});

describe('Logging-in', () => {
    it('Generates new token for existing user', async () => {
        const signinCmd = new SigninHandler(
            userRepo, 
            jwksCache);

        const event = await signinCmd.handle(
            new SigninCmd("KaratakosJP#1983", FederatedAccountType.STEAM, "0000", "0003"));

        expect(event).toBeInstanceOf(UserSignedInEvent);

        if (event instanceof UserSignedInEvent) {
            expect(event?.userId).toEqual("ee4ed797a4974e1299af4d76c67bd72e");
            expect(event?.federatedAccountId).toEqual("KaratakosJP#1983");
            expect(event?.accessToken).toBeDefined();
            expect(event?.refreshToken).toBeDefined();
            expect(event?.refreshToken).not.toEqual(adrianEnabledNotExpiredJWT);
        }
    });

    it('Generates new user account', async () => {
        const signinQuery = new SigninHandler(
            userRepo, 
            jwksCache);

        const event = await signinQuery.handle(
            new SigninCmd("SomeNewSteamUseAccount", FederatedAccountType.STEAM, "0000", "0001"));

        expect(event).toBeInstanceOf(UserSignedInEvent);

        if (event instanceof UserSignedInEvent) {
            expect(event?.userId).toBeDefined();
            expect(event?.federatedAccountId).toBeDefined();
            expect(event?.accessToken).toBeDefined();
            expect(event?.refreshToken).toBeDefined();   
        }
    });

    it('Sign-in failed for disabled user', async () => {
        const signinQuery = new SigninHandler(
            userRepo, 
            jwksCache);
        
        const event = await signinQuery.handle(
            new SigninCmd("LittleTimmy#1987", FederatedAccountType.STEAM, "0000", "0002"));

        expect(event).toBeInstanceOf(UserSignInUnauthorizedEvent);
    });
});



