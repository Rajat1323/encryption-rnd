import { Body, Controller, Get, Post, Query, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { Response } from 'express';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Post('/encrypt-json')
  getEncript(@Body() encript: any, @Res() res: Response) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return res.send({
      encrypted: this.appService.getEncript(encript),
    });
  }

  @Post('/decrypt-json')
  getDecript(@Body() encrypted: any, @Res() res: Response) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
    return res.send(this.appService.makeDecript(encrypted.encrypted));
  }

  @Get('/welcome')
  getHello(): string {
    return 'Hello World!';
  }
}
