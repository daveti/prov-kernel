/*
 * Copyright 2010    Hauke Mehrtens <hauke@hauke-m.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Compatibility file for Linux wireless for kernels 2.6.37.
 */

#include <linux/compat.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/nsproxy.h>
#include <linux/vmalloc.h>

#include "leds-compat.h"

#if defined(CONFIG_LEDS_CLASS) || defined(CONFIG_LEDS_CLASS_MODULE)

#undef led_brightness_set
#undef led_classdev_unregister

static DEFINE_SPINLOCK(led_lock);
static LIST_HEAD(led_timers);

struct led_timer {
	struct list_head list;
	struct led_classdev *cdev;
	struct timer_list blink_timer;
	unsigned long blink_delay_on;
	unsigned long blink_delay_off;
	int blink_brightness;
};

static void led_brightness_set(struct led_classdev *led_cdev,
			       enum led_brightness brightness)
{
	led_cdev->brightness = brightness;
	led_cdev->brightness_set(led_cdev, brightness);
}

static struct led_timer *led_get_timer(struct led_classdev *led_cdev)
{
	struct led_timer *p;
	unsigned long flags;

	spin_lock_irqsave(&led_lock, flags);
	list_for_each_entry(p, &led_timers, list) {
		if (p->cdev == led_cdev)
			goto found;
	}
	p = NULL;
found:
	spin_unlock_irqrestore(&led_lock, flags);
	return p;
}

static void led_stop_software_blink(struct led_timer *led)
{
	del_timer_sync(&led->blink_timer);
	led->blink_delay_on = 0;
	led->blink_delay_off = 0;
}

static void led_timer_function(unsigned long data)
{
	struct led_timer *led = (struct led_timer *)data;
	unsigned long brightness;
	unsigned long delay;

	if (!led->blink_delay_on || !led->blink_delay_off) {
		led->cdev->brightness_set(led->cdev, LED_OFF);
		return;
	}

	brightness = led->cdev->brightness;
	if (!brightness) {
		/* Time to switch the LED on. */
		brightness = led->blink_brightness;
		delay = led->blink_delay_on;
	} else {
		/* Store the current brightness value to be able
		 * to restore it when the delay_off period is over.
		 */
		led->blink_brightness = brightness;
		brightness = LED_OFF;
		delay = led->blink_delay_off;
	}

	led_brightness_set(led->cdev, brightness);
	mod_timer(&led->blink_timer, jiffies + msecs_to_jiffies(delay));
}

static struct led_timer *led_new_timer(struct led_classdev *led_cdev)
{
	struct led_timer *led;
	unsigned long flags;

	led = kzalloc(sizeof(struct led_timer), GFP_ATOMIC);
	if (!led)
		return NULL;

	led->cdev = led_cdev;
	init_timer(&led->blink_timer);
	led->blink_timer.function = led_timer_function;
	led->blink_timer.data = (unsigned long) led;

	spin_lock_irqsave(&led_lock, flags);
	list_add(&led->list, &led_timers);
	spin_unlock_irqrestore(&led_lock, flags);

	return led;
}

void led_blink_set(struct led_classdev *led_cdev,
		   unsigned long *delay_on,
		   unsigned long *delay_off)
{
	struct led_timer *led;
	int current_brightness;

	if (led_cdev->blink_set &&
	    !led_cdev->blink_set(led_cdev, delay_on, delay_off))
		return;

	led = led_get_timer(led_cdev);
	if (!led) {
		led = led_new_timer(led_cdev);
		if (!led)
			return;
	}

	/* blink with 1 Hz as default if nothing specified */
	if (!*delay_on && !*delay_off)
		*delay_on = *delay_off = 500;

	if (led->blink_delay_on == *delay_on &&
	    led->blink_delay_off == *delay_off)
		return;

	current_brightness = led_cdev->brightness;
	if (current_brightness)
		led->blink_brightness = current_brightness;
	if (!led->blink_brightness)
		led->blink_brightness = led_cdev->max_brightness;

	led_stop_software_blink(led);
	led->blink_delay_on = *delay_on;
	led->blink_delay_off = *delay_off;

	/* never on - don't blink */
	if (!*delay_on)
		return;

	/* never off - just set to brightness */
	if (!*delay_off) {
		led_brightness_set(led_cdev, led->blink_brightness);
		return;
	}

	mod_timer(&led->blink_timer, jiffies + 1);
}
EXPORT_SYMBOL(led_blink_set);

void compat_led_brightness_set(struct led_classdev *led_cdev,
			       enum led_brightness brightness)
{
	struct led_timer *led = led_get_timer(led_cdev);

	if (led)
		led_stop_software_blink(led);

	return led_cdev->brightness_set(led_cdev, brightness);
}
EXPORT_SYMBOL(compat_led_brightness_set);

void compat_led_classdev_unregister(struct led_classdev *led_cdev)
{
	struct led_timer *led = led_get_timer(led_cdev);
	unsigned long flags;

	if (led) {
		del_timer_sync(&led->blink_timer);
		spin_lock_irqsave(&led_lock, flags);
		list_del(&led->list);
		spin_unlock_irqrestore(&led_lock, flags);
		kfree(led);
	}

	led_classdev_unregister(led_cdev);
}
EXPORT_SYMBOL(compat_led_classdev_unregister);

#endif
