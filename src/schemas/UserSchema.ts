import { Document, model, Schema } from "mongoose";
import bcrypt from "bcrypt";
import omit from "lodash.omit";

enum EProvider {
  password = "password",
}

export interface IUser extends Document {
  email: string;
  password: string;
  username: string;
  provider: EProvider;
  provider_id?: string;
  provider_access_token?: string;
  provider_refresh_token?: string;
  firstname?: string;
  lastname?: string;
  isEmailValidated?: boolean;
  profilePicture?: string;
  fullname?: string;
  dateJoined: string | Date;

  toUserJSON(): IUser;
  toProfileJSON(): IUser;
  passwordMatch(pw: string, callback: (error: any, match: any) => void): void;
}

const UserSchema = new Schema(
  {
    email: {
      type: String,
      minlength: 12,
      unique: true,
      required: [true, "Email is required."],
      lowercase: true,
      maxlength: 64,
      validate: {
        validator: (email: string) => {
          const regex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
          return regex.test(email);
        },
        message: "{VALUE} is invalid.",
      },
    },
    password: {
      type: String,
      minlength: 8,
      required: true,
      maxlength: 100,
    },
    username: {
      type: String,
      unique: true,
      required: [true, "Username is required."],
      lowercase: true,
      minlength: 4,
      maxlength: 30,
      validate: {
        validator: (username) => {
          const regex = /^[a-z]+_?[a-z0-9]{1,}?$/gi;
          return regex.test(username);
        },
        message:
          "Username Must preceed with letters followed by _ or numbers eg: john23 | john_23",
      },
    },
    provider: {
      type: String,
      default: "password",
      enum: ["password", "facebook", "google", "github"],
    },
    provider_id: {
      type: String,
      default: null,
    },
    provider_access_token: String,
    provider_refresh_token: String,
    firstname: {
      type: String,
      maxlength: 40,
    },
    lastname: {
      type: String,
      maxlength: 50,
    },
    isEmailValidated: {
      type: Boolean,
      default: false,
    },
    profilePicture: {
      type: Object, // switched to cloudinary so I have to set as Object
      default: {},
    },
    dateJoined: {
      type: Date,
      default: Date.now,
      required: true,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: function (_doc, ret, _opt) {
        delete ret.password;
        delete ret.provider_access_token;
        delete ret.provider_refresh_token;
        return ret;
      },
    },
    toObject: {
      getters: true,
      virtuals: true,
      transform: function (_doc, ret, _opt) {
        delete ret.password;
        delete ret.provider_access_token;
        delete ret.provider_refresh_token;
        return ret;
      },
    },
  }
);

UserSchema.virtual("fullname").get(function () {
  const { firstname, lastname } = this;
  return firstname && lastname ? `${this.firstname} ${this.lastname}` : null;
});

UserSchema.methods.passwordMatch = function (this: IUser, password, cb) {
  const user = this;

  bcrypt.compare(password, user.password, function (err: any, isMatch: any) {
    if (err) return cb(err);

    cb(null, isMatch);
  });
};

UserSchema.methods.toUserJSON = function () {
  const user = omit(this.toObject(), ["password", "createdAt", "updatedAt"]);

  return user;
};

UserSchema.methods.toProfileJSON = function (this: IUser) {
  return {
    username: this.username,
    fullname: this.fullname,
    profilePicture: this.profilePicture,
  };
};

UserSchema.pre("save", function (this: IUser, next) {
  if (this.firstname === null) this.firstname = "";
  if (this.lastname === null) this.lastname = "";
  if (this.profilePicture === null) this.profilePicture = "";

  if (this.isNew || this.isModified("password")) {
    bcrypt.genSalt(10, (_err, salt) => {
      bcrypt.hash(this.password, salt, (_err, hash) => {
        this.password = hash;
        next();
      });
    });
  } else {
    next();
  }
});

const User = model<IUser>("User", UserSchema);
export default User;
