import { body } from "express-validator";
import User from "../models/user.model";

import bcrypt from "bcrypt";

export const validateLogin = [
  body("email")
    .not()
    .isEmpty()
    .withMessage("enter email")
    .isEmail()
    .withMessage("enter a valid email")
    .custom(async (email) => {
      let response = await User.findOne({ email });
      if (!response) {
        return Promise.reject("invalid credentials");
      }
      return true;
    }),
  body("password")
    .not()
    .isEmpty()
    .withMessage("enter password")
    .custom(async (password, { req }) => {
      let response = await User.findOne({ email: req.body.email });
      if (!response) {
        return Promise.reject("invalid credentials");
      }
      let isValid = await bcrypt.compare(password, response.password);
      if (!isValid) {
        return Promise.reject("invalid credentials");
      }
      return true;
    }),
];

export const validateRegister = [
  body("email")
    .not()
    .isEmpty()
    .withMessage("enter email")
    .isEmail()
    .withMessage("enter a valid email")
    .custom(async (email) => {
      let response = await User.findOne({ email });
      if (response) {
        return Promise.reject("user already registered");
      }
      return true;
    }),
  body("password").not().isEmpty().withMessage("enter password"),
  body("username").not().isEmpty().withMessage("enter user name"),
];
