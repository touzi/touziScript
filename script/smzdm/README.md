原作者地址 https://github.com/blackmatrix7/ios_rule_script/tree/master/script/smzdm


## 什么值得买


配置说明
Surge
安装模块
Surge推荐使用模块进行部署，
模块地址：https://raw.githubusercontent.com/touzi/touziScript/main/script/smzdm/smzdm_checkin.sgmodule

使用说明
Web端获取Cookie：
使用手机浏览器访问 https://zhiyou.smzdm.com/ 进行一次登录，通常会显示获取cookie成功。

可能因为重定向的问题，登录成功后访问的不是https://zhiyou.smzdm.com/user/ ，则重新在浏览器中访问一次https://zhiyou.smzdm.com/user/ 即可。

如果还是没有获取到Cookie，请查阅Surge等第三方App的执行日志。

App端获取账号密码：
打开什么值得买App，点击“我的“-“设置”-“退出登录”，先退出登录。随后点击“我的”中顶部的“立即登录”，选择“账号密码登录”，注意是账号密码登录，不要使用手机快捷登录或其他第三方登录方式。

登录完成后，提示获取账号密码成功，就说明没有问题了。如果没有提示，还是查阅一下第三方App的执行日志。在登录过程中，无论账号密码正确与否，都会进行获取和保存，如果账号密码有错，则重新登录一次即可，脚本会自动更新所保存的账号密码。

以上在什么值得买的iPhone 9.5.17版本测试通过。

#### Surge 这个版本暂时不能使用