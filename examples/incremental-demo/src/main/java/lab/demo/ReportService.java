package lab.demo;

import lab.demo.ReportController;

/** 未变更文件：import 了变更类，应被识别为依赖闭包上下文。 */
public class ReportService {
    private ReportController controller;

    public String summary(String file) {
        return controller.export(file);
    }
}
