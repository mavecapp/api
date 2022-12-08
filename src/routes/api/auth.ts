//@ts-ignore
import { NextFunction, Request, Response, Router } from "express";
import passport from "passport";

import { makeResponseJson, sessionizeUser } from "@/helpers/helpers";
import { ErrorHandler } from "@/middlewares/error.middleware";
import { IUser } from "@/schemas/UserSchema";
import { schemas, validateBody } from "@/validations/validations";

const router = Router({ mergeParams: true });

//@route POST /api/register
router.post(
  "/register",
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

//@route POST /api/login
router.post(
  "/login",
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

//@route DELETE /api/logout
router.delete("/logout", (req, res) => {
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

//@route GET /api/checkSession
// Check if user session exists
router.get("/check-session", (req, res, next) => {
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
