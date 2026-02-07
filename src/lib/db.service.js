const { default: mongoose } = require("mongoose")

async function dbConnection() {
    try{
        await mongoose.connect(process.env.dbUri)
        console.log("DB successfully connected ✅")
    }catch(err){
        console.log(`DB connection error: ${err.message}`)
        throw new Error(`DB connection error: ${err.message}`)
    }
};

module.exports = dbConnection;