const ApiError = require('../exceptions/apiError')
const tokenService = require('../service/tokenService')

module.exports = function (req, res, next) {
  try {
    const authorizationHeader = req.headers.authorization
    if (!authorizationHeader) {
      return next(ApiError.NoAccess())
    }

    const accessToken = authorizationHeader.split(' ')[1]
    if (!accessToken) {
      return next(ApiError.NoAccess())
    }

    const userData = tokenService.validateAccessToken(accessToken)
    if (!userData) {
      return next(ApiError.NoAccess())
    }

    req.user = userData
    next()
  } catch (error) {
    return next(ApiError.NoAccess())
  }
}