module.exports.maskInput = (str, mask = '*', n = 6) => {
  return typeof str === 'string' ? str.slice(0, -n).replace(/./g, mask) + str.slice(-n) : '';
};
