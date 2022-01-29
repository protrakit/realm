// This is for if you have a user that has registered with Email and wants to use an oAuth provider.
// Still working on the other way around, but it's the same concept.
// I have all of these functions laid out in different modules and tried to combine them together.
// Hopefully, I pieced it together correctly.

const app = new Realm.App({ id: 'REALM_ID' });
const credentials = Realm.Credentials;

function oauth () {
    var parameters = new URLSearchParams(window.location.search);
    var token = window.location.hash.match(/#access_token=([^&]+)/);
    token = !token ? parameters.get('code') : token[1];
    token = !token ? parameters.get('access_token') : token;

    if (token) {        
        if (window.opener && window.opener.parent) {
            window.opener.parent.oauthCallback(token);
            window.close();
        } else if (window.parent) {
            window.parent.oauthCallback(token);
            window.close();
        }
    }
}

function authorize (type) {
    var x = screen.width / 2 - 700 / 2;
    var y = screen.height / 2 - 450 / 2;
    var options = 'height=400,width=600,menubar=no,location=yes,resizable=yes,scrollbars=yes,status=yes,left=' + x + ',top=' + y;
    var uri = window.encodeURIComponent(window.location.origin);
    
    var clients = {
        github: // client id goes here,
        google: // client id goes here
    }

    var client = clients[type];
    var url;

    if (type === 'github') {
        url = 'https://github.com/login/oauth/authorize?client_id=' + client + '&response_type=code&redirect_uri=' + uri;
    } else if (type === 'google') {
        url = 'https://accounts.google.com/o/oauth2/v2/auth?client_id=' + client + '&response_type=code&scope=openid%20email%20profile&redirect_uri=' + uri;
    }

    window.oauthCallback = function (token) { login({ type: type, token: token }); };
    window.open(url,'oauth',options);
}

async function login (data) {
    if (!data) { throw new Error('No Credentials Provided!') };

    var user,creds,id,login;
    var oauth = data.token && data.type ? data.type : false;

    if (oauth) {
        // This will run the realm function to create or link this user.
        // In this case, the 'realmLogin' function will be used.
        creds = credentials.function(data);
    } else {
        creds = credentials.emailPassword(data.email, data.password);
    }

    user = await app.logIn(creds);

    // This is the record _id in the users collection
    id = user.identities && user.identities.length ? user.identities[0].id : false;

    login = await app.currentUser.functions['realmLogin']({
        _id: id,
        oauth: oauth,
        uid: user.id // This is the user identity id in realm users. This is used for custom data linking,
        type: user.providerType,
        device: user.deviceId,
        name: user.profile.name,
        state: user.state,
        email: data.email
    });

    if (login.error) { throw new Error(login.error.message) }

    // After logging in and linking users, refresh the custom data.
    // Check your record to make sure that the uid field contains your realm user ids
    await app.currentUser.refreshCustomData();
}




// This function will be in your realm functions
// This is used as your Credential Function and as well as the function to link users
async function realmLogin(data) {
    const user = context.user.custom_data;
    const db = context.services.get("atlas").db("app");
    const users = db.collection('users');

    var profile,response,user,result,query,insert,upsert,client,secret,token,redirect,http,body;

    // data.uid will be the ID of the user identity in your realm users.
    // Used for custom data.
    var id = data.uid;

    // data._id is used when using oAuth so you can get the existing user if there is one.
    var _id = data._id;

    // data.oauth will be the the oauth type returned AFTER your login with the data.token
    var _oauth = data.oauth;
    var oauth = data.token && data.type;
    var date = new Date();

    // oAuth will return the identity id of this user.
    // This id will be used after logging in.
    if (oauth) {
        clients = {
            github: // client id goes here,
            google: // client id goes here
        }

        redirect = // redirect encoded url goes here.
        client = clients[data.type];

        // Create a secret value in realm for your client secret.
        secret = context.values.get(data.type)

        if (data.type === 'github') {
            token = await context.http.post({
                url: `https://github.com/login/oauth/access_token`,
                headers: {
                    "Accept": ["application/json"],
                    "Content-Type": ['application/x-www-form-urlencoded']
                },
                body: `grant_type=authorization_code&code=${data.token}&redirect_uri=${redirect}&client_id=${client}&client_secret=${secret}`
            });

            response = EJSON.parse(token.body.text());

            http = await context.http.get({
                url: 'https://api.github.com/user',
                headers: { Authorization: [`Bearer ${response.access_token}`] },
                body: {},
                encodeBodyAsJSON: true
            });

            profile = EJSON.parse(http.body.text());

            if (!profile.email) {
                return {
                    error: {
                        name: data.type  + ' Login Error',
                        message: 'Your email is set to Private or is NOT DEFINED! It must be Public to use this provider.'
                    }
                }
            }

            query = {
                email: profile.email
            }

            insert = {
                email: profile.email,
                name: profile.name,
                picture: false,
                oauth: [{
                    type: data.type,
                    picture: profile.avatar_url,
                    githubUrl: profile.html_url,
                }]
            }

            upsert = {
                type: data.type,
                picture: profile.avatar_url,
                githubUrl: profile.html_url
            }
        } else if (data.type === 'google') {
            // Add jwt-decode to your realm dependancies
            const jwt_decode = require("jwt-decode");

            token = await context.http.post({
                url: `https://oauth2.googleapis.com/token?client_id=${client}&client_secret=${secret}&grant_type=authorization_code&code=${data.token}&redirect_uri=${redirect}`,
                headers: { "Content-Type": ['application/x-www-form-urlencoded'] },
                body: {},
                encodeBodyAsJSON: true
            });

            response = EJSON.parse(token.body.text());
            profile = jwt_decode(response.id_token);

            if (!profile.email) {
                return {
                    error: {
                        name: data.type + ' Login Error',
                        message: 'Your email is set to Private or is NOT DEFINED! It must be Public to use this provider.'
                    }
                }
            }

            query = {
                email: profile.email
            }

            insert = {
                email: profile.email,
                name: profile.name,
                picture: profile.picture,
                oauth: [{
                    type: data.type,
                    profile: profile.profile,
                    sub: profile.sub,
                    exp: profile.exp,
                }]
            }

            upsert = {
                type: data.type,
                sub: profile.sub,
                exp: profile.exp,
                picture: profile.picture,
                profile: profile.profile,
            }
        }

        if (!query) { throw new Error('Invalid Login!')};
        user = await users.findOne(query);

        if (user) {
            if (!user.oauth || !user.oauth.find(function(u) { return u.type === data.type })) {
                await _users.updateOne(query, {
                    $push: {
                        oauth: {
                            $each: [upsert],
                            $position: 0
                        }
                    }
                });
            }
            
            // Return back the record _id in the users collection so you can link.
            return user._id.toString();
        } else {
            // uid will be the field that connects to your user identity.
            // This must be set for your custom data in realm.
            // Realm documentation does not let us know that this field CAN be an array.
            insert.uid = [];

            result = await users.insertOne(insert);
            return result.insertedId.toString();
        }
    }

    // data.profile will be the profile returned after logging in with oauth
    data.profile = profile;

    query = data.email ? { email: data.email } : { _id: BSON.ObjectId(_id) };
    user = await users.findOne(query);

    // If this is a new user, then need to add the uid for linking custom data
    // If this is an existing user and using oauth, then add the uid to the array
    !user.uid ? await users.updateOne(query, { $set: { uid: [id], status: "Confirmed" } }) : 
    _oauth ? await users.updateOne(query, { $push: { uid: { $each: [id], $position: 0 }} }) :
    false;

    user = await users.findOne(query);
    if (!user) { throw new Error('Login Error!') }

    // Need to add in Realm Admin HTTPS request to log out user from other devices.

    upsert = { device: data.device, type: data.type, login_date: date };
    await users.updateOne(query, { $set: upsert });
    return await users.findOne(query);
}