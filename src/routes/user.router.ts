import express from "express";
import {
  loginUser,
  logoutUser,
  refreshTokenController,
  registerUser,
} from "../controllers/user.controllers";
import { validateLogin, validateRegister } from "../helpers/validationSchema";

const router = express.Router();

router.post("/register", validateRegister, registerUser);
router.post("/login", validateLogin, loginUser);
router.post("/refresh-token", refreshTokenController);
router.delete("/logout", logoutUser);

export default router;
