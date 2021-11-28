import express, {
  ErrorRequestHandler,
  NextFunction,
  Request,
  Response,
} from "express";
import morgan from "morgan";
import dotenv from "dotenv";
import createError from "http-errors";
import cors from "cors";

import "./helpers/init_mongodb";
import "./helpers/init_redis";

import authRoute from "./routes/user.router";
import { verifyAccessToken } from "./helpers/jwt_helper";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const corsOptions = {
  origin: "*",
  credentials: true,
  optionSuccessStatus: 200,
  methods: ["GET", "PUT", "POST", "DELETE"],
};

app.use(cors(corsOptions));
app.use(morgan("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// app.use((req, res, next) => {
//   res.append("Access-Control-Allow-Origin", ["*"]);
//   res.append("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
//   res.append("Access-Control-Allow-Headers", ["*"]);
//   res.append("Access-Control-Allow-Credentials", "true");
//   next();
// });

app.get(
  "/",
  verifyAccessToken as any,
  (req: Request, res: Response, next: NextFunction) => {
    res.status(200).send({ access: true });
  }
);

app.use("/auth", authRoute);

app.use(async (req: Request, res: Response, next: NextFunction) => {
  next(new createError.NotFound());
});

const errorMiddleware: ErrorRequestHandler = async (err, req, res, next) => {
  res.status(err.status || 500);
  res.send({
    error: {
      status: err.status || 500,
      message: err.message,
    },
  });
};

app.use(errorMiddleware);

app.listen(PORT, () => {
  console.log("listening to port" + PORT);
});
