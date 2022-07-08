const os = require('os');
const fs = require('fs');

const idRegex = /\bdefault\]\nveracode_api_key_id\ \=\ (\S+)/;
const keyRegex = /\bdefault\]\nveracode_api_key_id\ \=\ \S+\nveracode_api_key_secret\ \=\ (\S+)/;

var getCredsFromFile = () => {
    let creds = fs.readFileSync(os.homedir()+"\/.veracode\/credentials", "utf8");
    return { id: idRegex.exec(creds)[1], key: keyRegex.exec(creds)[1] };
}

// auth.js pulls from env variables. Else can use in terminal: export API_ID=YOUR_API_ID_VALUE && export KEY=YOUR_KEY_VALUE
var setCredsToEnv = () => {
    let creds = getCredsFromFile();
    process.env['API_ID'] = creds.id;
    process.env['KEY'] = creds.key;
}

module.exports = {
	getCredsFromFile,
	setCredsToEnv
}