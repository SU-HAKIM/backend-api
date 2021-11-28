import jwt from "jsonwebtoken";
import createError from "http-errors";
import dotenv from "dotenv";
import client from "./init_redis";
import { NextFunction, Request, Response } from "express";

dotenv.config();

export const signAccessToken = (userId: string) => {
  return new Promise((resolve, reject) => {
    const options = { expiresIn: "2m", issuer: "", audience: userId };
    const secret = process.env.ACCESS_TOKEN_SECRET_KEY;
    const payload = {};
    jwt.sign(payload, secret as string, options, (err, token) => {
      if (err) {
        console.log(err);
        return reject(new createError.InternalServerError());
      }
      resolve(token);
    });
  });
};

export const signRefreshToken = (userId: string) => {
  return new Promise((resolve, reject) => {
    const options = { expiresIn: "1y", issuer: "", audience: userId };
    const secret = process.env.REFRESH_TOKEN_SECRET_KEY;
    const payload = {};
    jwt.sign(payload, secret as string, options, (err, token) => {
      if (err) {
        console.log(err);
        return reject(new createError.InternalServerError());
      }
      client
        .set(userId, token as string, { EX: 365 * 24 * 60 * 60 })
        .then(() => {
          resolve(token);
        })
        .catch((err) => {
          reject(new createError.InternalServerError(err.message));
        });
    });
  });
};

type Req = Request & {
  payload: jwt.JwtPayload | undefined;
};

export const verifyAccessToken = (
  req: Req,
  res: Response,
  next: NextFunction
) => {
  try {
    let passedToken = req.headers["authorization"];
    console.log(passedToken);
    if (!passedToken) throw new createError.Unauthorized();
    let token = passedToken?.split(" ")[1];
    jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET_KEY as string,
      (err, payload) => {
        if (err) {
          if ((err.name = "JsonWebTokenError")) {
            return next(new createError.Unauthorized());
          } else {
            return next(new createError.Unauthorized(err.message));
          }
          // return res.status(500).send(err);
        }
        req.payload = payload;
        next();
      }
    );
  } catch (error) {
    console.log(error);
    next(error);
  }
};

export const verifyRefreshToken = async (refreshToken: string) => {
  return new Promise((resolve, reject) => {
    if (!refreshToken) reject(new createError.Unauthorized());
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET_KEY as string,
      (err, options) => {
        console.log(options);
        if (err) reject(new createError.Unauthorized());
        const userId = options?.aud;
        console.log(userId);
        client
          .GET(userId as string)
          .then((value) => {
            console.log(value === refreshToken); //!not equal
            console.log(value, "value");
            if (value === refreshToken) {
              //!error
              resolve(userId);
            }
            reject(new createError.Unauthorized());
          })
          .catch((err) => {
            reject(new createError.InternalServerError(err.message));
          });
      }
    );
  });
};
