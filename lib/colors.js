const enabled = process.stdout.isTTY && !process.env.NO_COLOR;

function wrap(code, text) {
  return enabled ? `\x1b[${code}m${text}\x1b[0m` : text;
}

export default {
  green: (text) => wrap(32, text),
  yellow: (text) => wrap(33, text),
  red: (text) => wrap(31, text),
  gray: (text) => wrap(90, text),
  bold: (text) => wrap(1, text)
};
