import Avatar from "./Avatar";

const Review = ({ review }) => (
  <div
    key={review.discord_user_id}
    className="border-b last:border-b-0 border-black last:mb-0 mb-2"
  >
    <div className="flex">
      <Avatar
        id={review.discord_user_id}
        avatar={review.avatar}
        className="h-12 mr-4 mt-2"
      />
      <p>{review.text}</p>
    </div>
    <div className="flex py-2">
      <div className="flex-grow" />
      By {review.username}#{review.discriminator} |&nbsp;<b>{review.score}/5</b>
    </div>
  </div>
);

export default Review;
