# 蓝奏云网盘 
## 一、简介  
蓝奏云网盘的分享链接直链api和UI重构（支持文件夹），可部署到CF（api和web分开部署）   
分享链接格式： 
若蓝奏云链接为www.lanzouq.com/AbcdZxy，则链接为https://<你的域名>.pages.dev/s/AbcdZxy  
## 二、部署流程  
1.下载整个项目  
2.把api内的文件打包成一个zip，上传部署到CF pages  
3.复制api部署的域名，打开UI文件夹里的_redirects文件，把“/api/share https://你的域名.pages.dev/ 307”的“https://你的域名.pages.dev/”替换成你的api域名 
4.打包UI文件夹里的文件成一个zip，上传部署到CF pages  
5.访问UI部署的网址即可使用  
## 三、使用流程  
若蓝奏云文件（夹）分享链接为https://www.lanzouq.com/AbcdZxy，则链接为https://<你的UI域名>.pages.dev/s/AbcdZxy 
