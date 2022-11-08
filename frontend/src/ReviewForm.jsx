import { useState, useEffect } from "react";

import { useMe, postReview, putReview } from "./api";
import Avatar from "./Avatar";

const ReviewForm = ({ myReview, provider }) => {
  const me = useMe();
  const [reviewText, setMyReview] = useState(myReview?.text ?? "");
  const [rating, setMyRating] = useState(myReview?.score ?? 5);

  // TODO: make sure mine shows up even if there are multiple pages of reviews
  const myExistingReview = myReview?.text ?? "";
  const myExistingRating = myReview?.score ?? 5;

  // reset when changing providers or when review data
  useEffect(() => {
    setMyReview(myExistingReview);
    setMyRating(myExistingRating);
  }, [myExistingReview, myExistingRating]);

  const submitForm = async (ev) => {
    ev.preventDefault();
    ev.target.disabled = true;
    if (myReview) {
      await putReview(provider.id, me.data.id, reviewText, rating);
    } else {
      await postReview(provider.id, reviewText, rating);
    }
    // Don't yell at me too much for this Jocelyn :)
    ev.target.innerText = "Success!";
    setTimeout(() => {
      ev.target.disabled = false;
      ev.target.innerText = "Submit";
    }, 1500);
  };

  return (
    <div className="pb-2">
      <div className="flex">
        <Avatar id={me.data.id} avatar={me.data.avatar} className="h-16 mr-4" />
        <textarea
          rows="10"
          className="resize-none border rounded border-black w-full px-2 py-1"
          value={reviewText}
          name="text"
          onChange={(ev) => {
            setMyReview(ev.target.value);
          }}
        />
      </div>
      <div className="flex pt-2 items-center">
        <div className="flex-grow" />
        <label htmlFor="rating">Rating (1-5):</label>
        <input
          min="1"
          max="5"
          type="number"
          value={rating}
          onChange={(ev) => {
            setMyRating(ev.target.valueAsNumber);
          }}
          name="rating"
          id="rating"
          className="ml-2 mr-8 border-b border-black w-8 h-6"
        />
        <button
          className="enabled:bg-blue-500 enabled:hover:bg-blue-700 disabled:bg-gray-500 rounded-md text-white py-1 px-2"
          onClick={submitForm}
        >
          Submit
        </button>
      </div>
    </div>
  );
};

export default ReviewForm;
