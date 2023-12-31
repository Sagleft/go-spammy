package main

import (
	"fmt"
	"log"

	gospammy "github.com/Sagleft/go-spammy"
)

func main() {
	text := `1. Начните с изучения базовых концепций условных операторов, таких как if-else, switch-case. Понимание различных условий и их влияния на выполнение кода основополагающе для программирования.

	2. После этого перейдите к изучению циклов. Изучите различные типы циклов, такие как for, while, do-while. Практикуйтесь в написании циклических конструкций, чтобы повторять или манипулировать кодом сколько угодно раз.
	
	3. Продолжайте углублять свои знания о функциях и типах данных. Изучите, как создать и использовать функции, а также различные типы данных, включая числа, строки и массивы. Понимание работы с функциями и типами данных поможет вам успешно писать программы на Go.
	
	При выполнении данной задачи рекомендуется изучать теорию, примеры кода и выполнять практические задания, чтобы закрепить полученные знания.`

	a := gospammy.New()
	keywords, err := a.GetTextKeywords(text, 10)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("text keywords:\n", keywords)

	spammyLevel, err := a.CheckTextSpamLevel(text)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("text spammy level, %:", spammyLevel)
}
