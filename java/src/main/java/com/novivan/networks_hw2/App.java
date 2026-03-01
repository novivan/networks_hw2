package com.novivan.networks_hw2;

import com.novivan.networks_hw2.dialoger.Dialoger;


public class App {
    public static void main(String[] args) {
        Dialoger dialoger = new Dialoger();
        try {
            dialoger.run();
            System.out.println("Работа приложения завершилась успешно!");
        } catch (Exception e) {
            System.out.printf("Работа приложения завершилась с ошибкой: %s%n", e.getMessage());
        }
    }
}