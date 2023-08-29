import os
import random
import msvcrt
import time

WIDTH = 80
HEIGHT = 20
SNAKE_INITIAL_LENGTH = 5
SNAKE_INITIAL_X = WIDTH // 2
SNAKE_INITIAL_Y = HEIGHT // 2
SNAKE_CHAR = "\033[1;32m#\033[0m"
FOOD_CHAR = "\033[1;31m*\033[0m"

class Snake:
    def __init__(self, x, y, length):
        self.x = x
        self.y = y
        self.length = length
        self.direction = "right"
        self.body = []
        for i in range(length):
            self.body.append((x - i, y))

    def move(self):
        head_x, head_y = self.body[0]
        if self.direction == "right":
            self.body.insert(0, (head_x + 1, head_y))
        elif self.direction == "left":
            self.body.insert(0, (head_x - 1, head_y))
        elif self.direction == "up":
            self.body.insert(0, (head_x, head_y - 1))
        elif self.direction == "down":
            self.body.insert(0, (head_x, head_y + 1))
        self.body.pop()

    def set_direction(self, direction):
        if direction in ["up", "down", "left", "right"]:
            if (
                direction == "up" and self.direction != "down"
                or direction == "down" and self.direction != "up"
                or direction == "left" and self.direction != "right"
                or direction == "right" and self.direction != "left"
            ):
                self.direction = direction

    def draw(self, screen):
        for x, y in self.body:
            screen[y][x] = SNAKE_CHAR

class Food:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def draw(self, screen):
        screen[self.y][self.x] = FOOD_CHAR

    @staticmethod
    def generate(snake_body, width, height):
        while True:
            x = random.randint(1, width - 2)
            y = random.randint(1, height - 2)
            if (x, y) not in snake_body:
                return Food(x, y)

class Game:
    def __init__(self):
        self.screen = [[" "] * WIDTH for _ in range(HEIGHT)]
        self.snake = Snake(SNAKE_INITIAL_X, SNAKE_INITIAL_Y, SNAKE_INITIAL_LENGTH)
        self.food = Food.generate(self.snake.body, WIDTH, HEIGHT)
        self.score = 0

    def update(self):
        if self.snake.body[0] == (self.food.x, self.food.y):
            self.snake.length += 1
            self.score += 1
            self.food = Food.generate(self.snake.body, WIDTH, HEIGHT)
        self.snake.move()
        if (
            self.snake.body[0][0] <= 0
            or self.snake.body[0][0] >= WIDTH - 1
            or self.snake.body[0][1] <= 0
            or self.snake.body[0][1] >= HEIGHT - 1
        ):
            raise Exception("Game over")
        for x, y in self.snake.body[1:]:
            if (x, y) == self.snake.body[0]:
                raise Exception("Game over")

    def draw(self):
        os.system("cls")
        # Draw top border
        print("\033[1;37;44m+" + "-" * (WIDTH - 2) + "+\033[0m")
        for y in range(HEIGHT):
            # Draw left border
            print("\033[1;37;44m|\033[0m", end="")
            for x in range(WIDTH):
                if (x, y) == (self.food.x, self.food.y):
                    self.food.draw(self.screen)
                else:
                    self.screen[y][x] = " "
                if (x, y) in self.snake.body:
                    self.screen[y][x] = SNAKE_CHAR
            # Draw game screen
            for x in range(WIDTH):
                print(
                    f"\033[1;37;40m{self.screen[y][x]}\033[0m",
                    end="",
                )
            # Draw right border
            print("\033[1;37;44m|\033[0m")
        # Draw bottom border
        print("\033[1;37;44m+" + "-" * (WIDTH
        ) + "+\033[0m")
        print("Score:", self.score)

    def run(self):
        while True:
            try:
                self.update()
                self.draw()
                time.sleep(0.1)
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b"w":
                        self.snake.set_direction("up")
                    elif key == b"s":
                        self.snake.set_direction("down")
                    elif key == b"a":
                        self.snake.set_direction("left")
                    elif key == b"d":
                        self.snake.set_direction("right")
                    elif key == b"q":
                        return
            except Exception as e:
                print(e)
                return

if __name__ == "__main__":
    game = Game()
    game.run()