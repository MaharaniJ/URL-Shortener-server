const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { UserDetails } = require("../../models/userModel");

const login = async (req, res) => {
  try {
    let { email, password } = req.body;
    // First, check the email in the database
    let user = await UserDetails.findOne({ email: email });
    if (user) {
      // Compare the two passwords
      let compare = await bcrypt.compare(password, user.password);
      if (compare) {
        let token = jwt.sign({ id: user._id }, process.env.SECRETKEY, { expiresIn: "5m" });
        res.json({
          statusCode: 201,
          message: "Login successfully",
          token,
          id: user._id,
        });
      } else {
        res.json({
          statusCode: 401,
          message: "Wrong password",
        });
      }
    } else {
      res.json({
        statusCode: 401,
        message: "Invalid email",
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      statusCode: 500,
      message: "Internal Server Error",
      error,
    });
  }
};

module.exports = { login };
