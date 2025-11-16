import { ICommand, ICommandHandler } from './command.js';
import { 
    FederatedAccountType, 
    FederatedAccount, 
    RefreshToken, 
    UserAccount, 
    User, 
    UserAccountStatus } from '../../entities/user.js';
import { UserRepo} from '../../repository/user/user.repo.js';
import { v4 as uuid } from 'uuid';
import { generateUsername } from 'friendly-username-generator';
import { UserSignedInEvent} from '../../events/user-signed-in.event.js';
import { 
    UserSignInUnauthorizedEvent, 
    UserSignInUnauthorizedReason} from '../../events/user-sign-in-unauthorized.event.js';
import { IJwksCache } from '../../util/jkws-paramstore-cache.js';
import { Config } from '../../util/config.js';

import jwt from 'jsonwebtoken';
import jwkToPem from 'jwk-to-pem';

class SigninCmd implements ICommand {
    constructor(
        public readonly accountId: string, 
        public readonly provider: FederatedAccountType, 
        public readonly token: string, 
        public readonly commandId: string) {}
}

class SigninHandler implements ICommandHandler<UserSignedInEvent | UserSignInUnauthorizedEvent> {
    constructor(
        public readonly repository: UserRepo,
        public readonly jwksCache: IJwksCache) {}

    async handle(cmd: SigninCmd): Promise<UserSignedInEvent | UserSignInUnauthorizedEvent> {
        // TODO: Validate the god damn Steam user token

        try {
            // Check if a user account already exists
            // 
            let user = await this.repository.getUserForFederatedAccountId(
                cmd.accountId, 
                cmd.provider);
          
            if (user) {
                if (user.userAccount.status === UserAccountStatus.DISABLED) {
                    return new UserSignInUnauthorizedEvent(
                            cmd.accountId, 
                            new Date().toJSON(), 
                            `User account ${user.userAccount.userId} has been disabled.`,
                            UserSignInUnauthorizedReason.ACCOUNT_DISABLED,
                            cmd.commandId);
                }

                if (user.refreshToken) {
                    // Existing token needs invalidating
                    //
                    this.repository.deleteRefreshToken(user.refreshToken);
                }

                // Update the Steam token if it has changed
                //
                if (user.federatedAccount.token != cmd.token) {
                    const updatedFederatedAccount = new FederatedAccount(
                        user.federatedAccount.userId,
                        user.federatedAccount.accountId,
                        user.federatedAccount.type,
                        cmd.token
                    )

                    user = new User(
                        user.accessToken,
                        user.refreshToken,
                        updatedFederatedAccount,
                        user.userAccount);

                    this.repository.updateFederatedAccount(user.federatedAccount);
                }
            }
            // We're going to create a user account for them
            //
            else {
                console.log("User doesn't exist so adding a new account.");

                const userAccount = new UserAccount(
                    uuid(),
                    generateUsername({
                        useHyphen: false,
                        useRandomNumber: true }),
                    UserAccountStatus.ENABLED);


                const federatedAccount = new FederatedAccount(
                    userAccount.userId,
                    cmd.accountId,
                    cmd.provider,
                    cmd.token);

                user = new User(
                    undefined,
                    undefined,
                    federatedAccount,
                    userAccount);
                
                this.repository.addUser(user);
            }

            const jwk = await this.jwksCache.getSigningKey();
            const pem = jwkToPem(jwk, {private: true})
            const signingOptions: jwt.SignOptions = {
                algorithm: 'ES256',
                keyid: jwk.kid };

            // Generate new refresh token
            //
            const signedRefreshToken = jwt.sign(
                {
                    userId: user.userAccount.userId,
                    exp: Config.createExpiry(Config.refreshTokenTTLHours) },
                pem,
                signingOptions);
                    
            const refreshToken = new RefreshToken(
                user.userAccount.userId,
                signedRefreshToken
            );

            this.repository.addRefreshToken(refreshToken);

            // Finally, generate new access token
            //
            const accessToken = jwt.sign(
                {
                    userId: user.userAccount.userId, 
                    policy: user.userAccount.policy,
                    exp: Config.createExpiry(Config.accessTokenTTLHours) },
                pem,
                signingOptions);

            user = new User(
                accessToken,
                refreshToken,
                user.federatedAccount,
                user.userAccount);

            return new UserSignedInEvent(
                    cmd.accountId,
                    user.userAccount.userId,
                    new Date().toJSON(), 
                    user.refreshToken?.token,
                    user?.accessToken,
                    cmd.commandId);
        }
        catch (e) {
            const error = e as Error;

            return new UserSignInUnauthorizedEvent(
                    cmd.accountId, 
                    new Date().toJSON(), 
                    error.message,
                    UserSignInUnauthorizedReason.ERROR,
                    cmd.commandId);
        }       
    }
}

export {SigninHandler, SigninCmd};
