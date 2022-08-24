const UserModel = require('../models/userModel')
const bcrypt = require('bcrypt')
const uuid = require('uuid')
const mailService = require('./mailService')
const tokenService = require('./tokenService')
const UserDto = require('../dtos/userDto')

class UserService {
  async registration(email, password) {
    const candidate = await UserModel.findOne({ email })

    if (candidate) {
      throw new Error(`Пользователь с таким почтовым адресом ${email} уже существует`)
    }

    const hashPassword = await bcrypt.hash(password, 6)
    const activationLink = uuid.v4() // c23wa-ads23eq1-qwe2e3-3eq1
    const user = await UserModel.create({ email, password: hashPassword, activationLink })

    await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`)

    const userDto = new UserDto(user) // id, email, isActivated
    const tokens = tokenService.generateTokens({ ...userDto })

    await tokenService.saveToken(userDto.id, tokens.refreshToken)

    return { ...tokens, user: userDto }
  }

  async activate(activationLink) {
    const user = await UserModel.findOne({ activationLink })

    if (!user) {
      throw new Error('Неккоректная ссылка активации')
    }

    user.isActivated = true
    await user.save()
  }
}

module.exports = new UserService()