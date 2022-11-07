import Avatar from "./Avatar";

const Review = ({ review }) => (
  <div
    key={review.discord_user_id}
    className="border-b last:border-b-0 border-black"
  >
    <div className="flex">
      <Avatar
        id={review.discord_user_id}
        avatar={review.avatar}
        className="h-16 mr-4 mt-2"
      />
      <p>{review.text}</p>
    </div>
    <div className="flex py-2">
      <div className="flex-grow" />
      By {review.username}#{review.discriminator} | {review.score}/5
    </div>
  </div>
);

export default Review;
