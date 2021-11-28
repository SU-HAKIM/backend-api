import { NextFunction, Request, Response } from "express";
import { validationResult } from "express-validator";
import createError from "http-errors";
import { formatter } from "../helpers/errorFormatter";
import client from "../helpers/init_redis";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../helpers/jwt_helper";
import User from "../models/user.model";

export const registerUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req).formatWith(formatter);
  if (!errors.isEmpty()) {
    return res.json(errors.mapped());
  }
  try {
    const newUser = new User(req.body);
    const savedUser = await newUser.save();
    const accessToken = await signAccessToken(String(savedUser._id));
    const refreshToken = await signRefreshToken(String(savedUser._id));
    console.log(savedUser._id);
    res.cookie("rt", refreshToken);
    res
      .status(200)
      .json({ registered: true, tokens: { accessToken, refreshToken } });
  } catch (error) {
    console.log(error);
    next(error);
  }
};

export const loginUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const errors = validationResult(req).formatWith(formatter);
  if (!errors.isEmpty()) {
    return res.json({ errors: errors.array() });
  }
  try {
    const oldUser = await User.findOne({ email: req.body.email });
    const accessToken = await signAccessToken(String(oldUser._id));
    const refreshToken = await signRefreshToken(String(oldUser._id));
    res.status(200).send({ accessToken, refreshToken });
  } catch (error) {
    console.log(error);
    next(error);
  }
};

export const logoutUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    let { refreshToken } = req.body;
    if (!refreshToken) throw new createError.BadRequest();
    const userId = await verifyRefreshToken(refreshToken);
    const val = await client.DEL(userId as string);
    console.log(val);
    res.sendStatus(204);
  } catch (error) {
    console.log(error);
    next(error);
  }
};

export const refreshTokenController = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    let { refreshToken } = req.body;
    if (!refreshToken) throw new createError.BadRequest();
    const userId = await verifyRefreshToken(refreshToken);
    console.log(userId, "userId");
    if (!userId) return next(new createError.Unauthorized());
    const accessToken = await signAccessToken(String(userId));
    const newRefreshToken = await signRefreshToken(String(userId));

    res.status(200).send({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.log(error);
    next(error);
  }
};
