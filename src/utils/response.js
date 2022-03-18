//  creating a response message
const successResMsg = (res, statusCode, message) => {
  const { data, ...responseMsg } = message;
  res.status(statusCode).json({
    data,
    responseMsg,
  });
};

const errorResMsg = (res, statusCode, message) => {
  res.status(statusCode).json({
    message,
  });
};
//    exporting modules
module.exports = { successResMsg, errorResMsg };
