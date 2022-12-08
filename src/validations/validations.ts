import { NextFunction, Request, Response } from "express";
import Joi, { Schema } from "joi";

import { ErrorHandler } from "@/middlewares";

const email = Joi.string()
  .email({ minDomainSegments: 2, tlds: { allow: ["com", "net"] } })
  .required()
  .messages({
    "string.base": `Email should be a type of 'text'`,
    "string.empty": `Email cannot be an empty field`,
    "string.min": `Email should have a minimum length of {#limit}`,
    "any.required": `Email is a required field.`,
  });

const password = Joi.string().min(8).max(50).required().messages({
  "string.base": `Password should be a type of 'text'`,
  "string.empty": `Password cannot be an empty field`,
  "string.min": `Password should have a minimum length of {#limit}`,
  "any.required": `Password is a required field`,
});
const username = Joi.string().required().messages({
  "string.base": 'Username should be of type "text"',
  "string.empty": `Username cannot be an empty field`,
  "string.min": `Username should have a minimum length of {#limit}`,
  "any.required": "Username field is required",
});

export const schemas = {
  loginSchema: Joi.object()
    .keys({
      username,
      password,
    })
    .options({ abortEarly: false }),
  registerSchema: Joi.object()
    .keys({
      email,
      password,
      username,
    })
    .options({ abortEarly: false }),
};

export const validateBody = (schema: Schema) => {
  return (req: Request & { value: any }, res: Response, next: NextFunction) => {
    const result = schema.validate(req.body);

    if (result.error) {
      console.log(result.error);
      return next(new ErrorHandler(400, result.error.details[0].message));
    } else {
      if (!req.value) {
        req.value = {};
      }
      req.value["body"] = result.value;
      next();
    }
  };
};
