//@ts-ignore
import { NextFunction, Request, Response, Router } from "express";
import passport from "passport";

import { makeResponseJson, sessionizeUser } from "@/helpers/helpers";
import { ErrorHandler } from "@/middlewares/error.middleware";
import { IUser } from "@/schemas/UserSchema";
import { schemas, validateBody } from "@/validations/validations";

const router = Router({ mergeParams: true });

// @route POST /api/v1/auth/register
router.post(
  "/v1/auth/register",
  validateBody(schemas.registerSchema),
  (req, res, next) => {
    passport.authenticate("local-register", (err, user, info) => {
      if (err) {
        return next(err);
      }

      if (user) {
        // if user has been successfully created
        req.logIn(user, (err) => {
          // <-- Log user in
          if (err) {
            return next(err);
          }

          const userData = sessionizeUser(user);
          return res.status(200).send(makeResponseJson(userData));
        });
      } else {
        next(new ErrorHandler(409, info.message));
      }
    })(req, res, next);
  }
);

// @route POST /api/v1/auth/login
router.post(
  "/v1/auth/login",
  validateBody(schemas.loginSchema),
  (req: Request, res: Response, next: NextFunction) => {
    console.log("FIREED");
    passport.authenticate("local-login", (err, user, info) => {
      if (err) {
        return next(err);
      }

      if (!user) {
        return next(new ErrorHandler(400, info.message));
      } else {
        req.logIn(user, (err) => {
          // <-- Log user in
          if (err) {
            return next(err);
          }

          const userData = sessionizeUser(user);
          return res.status(200).send(
            makeResponseJson({
              auth: userData,
              user: (req.user as IUser).toUserJSON(),
            })
          );
        });
      }
    })(req, res, next);
  }
);

// @route DELETE /api/v1/auth/logout
router.delete("/v1/auth/logout", (req, res) => {
  req.logOut((err) => {
    if (err) {
      return res.status(422).send(
        makeResponseJson({
          status_code: 422,
          message: "Unable to logout. Please try again.",
        })
      );
    }

    return res.sendStatus(200);
  });
});

// @route GET /api/v1/auth/check-session
// Check if user session exists
router.get("/v1/auth/check-session", (req, res, next) => {
  if (req.isAuthenticated()) {
    const user = sessionizeUser(req.user);
    res
      .status(200)
      .send(
        makeResponseJson({ auth: user, user: (req.user as IUser).toUserJSON() })
      );
  } else {
    next(new ErrorHandler(404, "Session invalid/expired."));
  }
});

export default router;
