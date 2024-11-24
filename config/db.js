import { Sequelize } from "sequelize";
import configData from "./config.json" with {type:"json"};
import "dotenv/config";

const env=process.env.NODE_ENV||"development";
const config=configData[env];

const sequelize =new Sequelize(
    config.database,
    config.username,
    config.password,
    {
        host: config.host,
        dialect:config.dialect
    }
)

export default sequelize;