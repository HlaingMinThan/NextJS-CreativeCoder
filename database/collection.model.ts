import { model, Schema, Types, Document, models } from "mongoose";

export interface ICollection {
  author: Types.ObjectId;
  question: Types.ObjectId;
}

export interface ICollectionDoc extends ICollection, Document {}

const CollectionSchema = new Schema(
  {
    author: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    question: {
      type: Schema.Types.ObjectId,
      ref: "Question",
      required: true,
    },
  },
  { timestamps: true }
);

// Create a compound index to ensure a user can't save the same question multiple times
CollectionSchema.index({ author: 1, question: 1 }, { unique: true });

const Collection =
  models?.Collection || model<ICollection>("Collection", CollectionSchema);

export default Collection;
