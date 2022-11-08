import { useId } from "react";

const PillButtonInput = ({
  name,
  value,
  label,
  currentValue,
  onSetCurrentValue,
}) => {
  const id = `pill-${useId()}`;

  return (
    <div className="contents">
      <input
        type="radio"
        name={name}
        id={id}
        value={value}
        checked={value === currentValue}
        className="hidden peer"
        onClick={() => onSetCurrentValue(value === currentValue ? null : value)}
      />
      <label
        htmlFor={id}
        className="border py-1 px-3 rounded-full text-sm duration-100 text-blue-500 hover:text-blue-700 border-pink-500 hover:border-pink-700 peer-checked:text-white peer-checked:bg-blue-500 peer-checked:hover:bg-blue-700 peer-checked:hover:drop-shadow-md peer-checked:border-blue-500 peer-checked:hover:border-blue-700 cursor-pointer"
      >
        {label}
      </label>
    </div>
  );
};

export default PillButtonInput;
