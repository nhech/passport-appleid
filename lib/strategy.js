/**
 * Module dependencies.
 */
const util = require('util');
const OAuth2Strategy = require('passport-oauth2');
const appleSignin = require("apple-signin-auth");
const Profile = require('./profile');
const {URL} = require("url");
const InternalOAuthError = OAuth2Strategy.InternalOAuthError;
const AuthorizationError = OAuth2Strategy.AuthorizationError;

const ENDPOINT_URL = 'https://appleid.apple.com';

const getAuthorizationUrl = (options) => {
	// Handle input errors
	if (!options.clientID) {
		throw Error('clientID is empty');
	}
	if (!options.redirectUri) {
		throw Error('redirectUri is empty');
	}

	const url = new URL(ENDPOINT_URL);
	url.pathname = '/auth/authorize';

	url.searchParams.append('response_type', 'code');
	url.searchParams.append('state', options.state || 'state');
	url.searchParams.append('client_id', options.clientID);
	url.searchParams.append('redirect_uri', options.redirectUri);
	url.searchParams.append('scope', `${`${options.scope}`}`);

	if (options.scope?.includes('email')) {
		// Force set response_mode to 'form_post' if scope includes email
		url.searchParams.append('response_mode', 'form_post');
	} else if (options.responseMode) {
		// Set response_mode to input responseMode
		url.searchParams.append('response_mode', options.response_mode);
	}

	return url.toString();
};

/**
 * `Strategy` constructor.
 *
 * The Apple authentication strategy authenticates requests by delegating to
 * Apple using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`           identifier of Apple Service ID
 *   - `callbackURL`        URL to which Apple will redirect the user after granting authorization
 *   - `teamId`             apple Developer Team ID.
 *   - `keyIdentifier`      identifier of private Apple key associated with clientID
 *   - `privateKey`     	Apple key associated with clientID
 *   - `scope`              (optional) array of permission scopes to request.  valid scopes include:
 *
 * Examples:
 *
 *     passport.use(new AppleStrategy({
 *         clientID: '123-456-789',
 *         callbackURL: 'https://www.example.net/auth/apple/callback',
 *         teamId: "123456AB",
 *         keyIdentifier: 'RB1233456',
 *         privateKey: ''
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
	this._options = options || {};
	this._verify = verify;
	this.name = 'apple';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
	var self = this;

	if (req.query && req.query.error) {
		if (req.query.error == 'access_denied' || req.query.error == 'user_cancelled_authorize') return this.fail({ message: 'User cancelled authorize'});
		return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
	}

	const redirectUri = options.callbackURL || self._options.callbackURL;
	const passReqToCallback = self._options.passReqToCallback || options.passReqToCallback || false;

	if (req.query && req.query.code){
		const state = req.query.state;

		function verified(error, user, info) {
			if (error) return self.error(error);
			if (!user) return self.fail(info);

			info = info || {};
			if (state) { info.state = state; }
			self.success(user, info);
		}

		const params = {clientID: self._options.clientID, redirectUri: redirectUri, clientSecret: appleSignin.getClientSecret(self._options)};
		appleSignin.getAuthorizationToken(req.query.code, params).then(token => {
			var idToken = token['id_token'];
			if (!idToken) { return self.error(new Error('ID Token not present in token response')); }

			appleSignin.verifyIdToken(idToken, self._options.clientID).then(jwtClaims => {
				const profile = {};
				profile.id = jwtClaims.sub;
				profile.email = jwtClaims.email;
				profile.email_verified = jwtClaims.email_verified;

				if(passReqToCallback) {
					self._verify(req, token.access_token, token.refresh_token, profile, verified);
				} else {
					self._verify(token.access_token, token.refresh_token, profile, verified);
				}
			}).catch(error => {
				return self.error(new InternalOAuthError('token is not verified', error));
			});
		}).catch(error => {
			return self.error(new InternalOAuthError('failed to obtain access token', error));
		});
	} else {
		let params = self._options;
		params.redirectUri = redirectUri;
		params.scope = options.scope || params.scope || "";
		params.state = options.state;

      	self.redirect(getAuthorizationUrl(self._options));
	}
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;