import { useRef } from "react";
import { useField } from "react-final-form";

const PillButtonInput = ({ name, value, label }) => {
  const { input } = useField(name);
  const ref = useRef(null);
  const onClick = () => {
    if (ref.current) {
      ref.current.value = value;
      input.onChange(input.value === value ? "" : value);
    }
  };

  const selectedClasses =
    "text-white bg-blue-500 hover:bg-blue-700 hover:drop-shadow-md border-blue-500 hover:border-blue-700";
  const unselectedClasses =
    "text-blue-500 hover:text-blue-700 border-pink-500 hover:border-pink-700 ";
  const baseClasses = "border py-1 px-3 rounded-full text-sm duration-100 ";

  const className =
    input.value === value
      ? baseClasses + selectedClasses
      : baseClasses + unselectedClasses;

  return (
    <>
      <input type="hidden" {...input} ref={ref} />
      <button className={className} onClick={onClick}>
        {label}
      </button>
    </>
  );
};

export default PillButtonInput;
