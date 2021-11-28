import { ValidationError } from "express-validator";

export const formatter = (error: ValidationError) => error.msg;
