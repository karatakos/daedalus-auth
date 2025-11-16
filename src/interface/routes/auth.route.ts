import express, {Request, Response} from 'express';

import { AccessTokenHandler, AccessTokenQuery } from '../../actions/queries/access-token.query.js';
import { SigninHandler, SigninCmd } from '../../actions/commands/sign-in.command.js';

import { UserSignedInEvent } from '../../events/user-signed-in.event.js';
import { UserSignInUnauthorizedEvent } from '../../events/user-sign-in-unauthorized.event.js';

import { UserRepoFactory } from '../../repository/user/user.repo.factory.js';
import { FederatedAccountType } from '../../entities/user.js';

import { parseCookies } from '../util/cookie-parser.js';

import { JwksParameterStoreCache } from '../../util/jkws-paramstore-cache.js';

import { SSMClient } from '@aws-sdk/client-ssm';

const router = express.Router();

const userRepo = UserRepoFactory.make();
const jwksCache = new JwksParameterStoreCache(new SSMClient());

router
    .route('/sign-in')
    .post(async (req: Request, res: Response) => {    
            // TODO: Better validation
            //
            if (!req.is('application/json') ||
                !req.body?.oauthAccountId || 
                !req.body?.oauthProvider ||
                !req.body?.oauthToken) {

                console.log(req.is('application/json'));
                console.log(req.body);

                res.status(401).send({error: "Badly formed request."});

                return;
            }

            if (req.body?.oauthProvider != FederatedAccountType.STEAM) {
                res.status(401).send({error: "Only Steam authentication supported."});

                return;
            }
        
            // TODO: To fix this we need a solution to access a centralized
            // event bus instance like a queue that will allow the client to 
            // call us back on this endpoint and still access events even if the
            // loadbalancer routes to a different node instance
            //
            // This is a very dirty work around in the meantime
            // 
            const signin = new SigninHandler(
                userRepo,
                jwksCache);

            try {
                // TODO: Do this asyncronously and expect the client to callback?
                //
                const event = await signin.handle(
                    new SigninCmd(
                        req.body.oauthAccountId,
                        req.body.oauthProvider,
                        req.body.oauthToken,
                        req.body.commandId));
    
                if (!event)
                    throw new Error("Unauthorized. Sign-in failed for unknown reason.");

                switch (event.constructor) {
                    case UserSignedInEvent: {
                        const e = event as UserSignedInEvent;

                        res.cookie('refreshToken', e.refreshToken, { httpOnly: true })
                        res.cookie('accessToken', e.accessToken, { httpOnly: true })
        
                        res.send({ 
                            result: 'OK',
                            accessToken: e.accessToken,
                            refreshToken: e.refreshToken
                        }); 

                        break;
                    }

                    case UserSignInUnauthorizedEvent: {
                        const e = event as UserSignInUnauthorizedEvent;

                        res.status(401).send({
                            'reasonCode': e.reason, 
                            'error': e.message 
                        });

                        break;
                    }
                }
            }
            catch (e) {
                const error = e as Error;

                console.log(error);
                res.status(400).send({error: error.message});
            }
        });

router
    .route('/refresh-token')
    .get(async (req: Request, res: Response) => {    
        try {
            let refreshToken: string | undefined = undefined;

            // Unlikely required but useful if available due to the free encryption
            //
            if (req.headers.cookie) {
                const cookies = parseCookies(req.headers.cookie);
        
                if (cookies?.refreshToken)
                    refreshToken = cookies.refreshToken;
            }

            // Check auth header for refresh token assuming client is keeping it safe!
            //
            const bearerToken: string[] | undefined = req.headers.authorization?.split(' ');
            if (bearerToken && bearerToken[0] == "Bearer" && bearerToken[1])
                refreshToken = bearerToken[1];
        
            if (!refreshToken) {
                res.status(401).send("Unauthorized. No refresh token presented.");
                return;
            }

            const refreshTokenHandler = new AccessTokenHandler(
                userRepo,
                jwksCache);

            const accessToken = await refreshTokenHandler.handle(
                new AccessTokenQuery(refreshToken));

            res.cookie(
                'accessToken', 
                accessToken, 
                { httpOnly: true })
    
            res.send({ 
                result: 'OK',
                accessToken: accessToken
            });
        }
        catch (e) {
            res.status(401).send(e);
        }
    });

export default router;
