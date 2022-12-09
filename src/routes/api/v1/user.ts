import { NextFunction, Request, Response, Router } from "express";

import { makeResponseJson } from "@/helpers/helpers";
import { ErrorHandler, isAuthenticated } from "@/middlewares";
import { User } from "@/schemas";
import { IUser } from "@/schemas/UserSchema";
import { schemas, validateBody } from "@/validations/validations";

const router = Router({ mergeParams: true });

// @route GET /api/v1/user/:username
router.get(
  "/v1/user/:username",
  isAuthenticated,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const reqUser = req.user as IUser;
      const { username } = req.params;
      const user = await User.findOne({ username });

      if (!user) return next(new ErrorHandler(404, "User not found."));

      const toObjectUser = {
        ...user.toUserJSON(),
      };

      toObjectUser.isOwnProfile = reqUser.username === username;

      res.status(200).send(makeResponseJson(toObjectUser));
    } catch (e) {
      console.log(e);
      next(e);
    }
  }
);

interface IUpdate {
  firstname?: string;
  lastname?: string;
}

// @route PATCH /api/v1/user/:username/edit
router.patch(
  "/v1/user/:username/edit",
  isAuthenticated,
  validateBody(schemas.editProfileSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { username } = req.params;
      const { firstname, lastname } = req.body;
      const update: IUpdate = {};
      if (username !== (req.user as IUser).username)
        return next(new ErrorHandler(401));

      if (typeof firstname !== "undefined") update.firstname = firstname;
      if (typeof lastname !== "undefined") update.lastname = lastname;

      const newUser = await User.findOneAndUpdate(
        { username },
        {
          $set: update,
        },
        {
          new: true,
        }
      );

      res.status(200).send(makeResponseJson(newUser.toUserJSON()));
    } catch (e) {
      console.log(e);
      next(e);
    }
  }
);

export default router;
