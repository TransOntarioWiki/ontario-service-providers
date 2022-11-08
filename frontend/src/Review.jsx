import Avatar from "./Avatar";
import ReactMarkdown from "react-markdown";

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
      <div>
        <ReactMarkdown className="flex flex-col space-y-2">
          {review.text}
        </ReactMarkdown>
      </div>
    </div>
    <div className="flex py-2">
      <div className="flex-grow" />
      By {review.username}#{review.discriminator} |&nbsp;<b>{review.score}/5</b>
    </div>
  </div>
);

export default Review;
