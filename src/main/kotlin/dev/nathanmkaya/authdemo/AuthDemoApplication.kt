package dev.nathanmkaya.authdemo

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class AuthDemoApplication

fun main(args: Array<String>) {
    runApplication<AuthDemoApplication>(*args)
}
