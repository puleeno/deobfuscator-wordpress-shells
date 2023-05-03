<?php
/*
 *  Upgrade to pro options
 */ 

function consultstreet_upgrade_pro_options( $wp_customize ) {

	$wp_customize->add_section(
        'upgrade_premium',
        array(
            'title' 		=> __('Upgrade to Pro','consultstreet'),
			'priority'      => 1,
		)
    );
	
	class ConsultStreet_WP_Button_Customize_Control extends WP_Customize_Control {
	public $type = 'upgrade_premium';

	   function render_content() {
		?>
			<div class="pro_info">
				<ul>
					<li><a class="documentation" href="https://helpdoc.themearile.com/" target="_blank"><i class="dashicons dashicons-visibility"></i><?php _e( 'View Documentation','consultstreet' ); ?> </a></li>
					
					<li><a class="support" href="https://themearile.com/forums/" target="_blank"><i class="dashicons dashicons-lightbulb"></i><?php _e( 'Get Full Support','consultstreet' ); ?> </a></li>
					
					<li><a class="free-pro" href="https://themearile.com/consultstreet-pro-theme/#free-pro-features" target="_blank"><i class="dashicons dashicons-visibility"></i><?php _e( 'Free Vs Pro Features','consultstreet' ); ?> </a></li>
					
					<li><a class="upgrade-to-pro" href="https://themearile.com/consultstreet-pro-theme/" target="_blank"><i class="dashicons dashicons-update-alt"></i><?php _e( 'Upgrade to Pro','consultstreet' ); ?> </a></li>
					
					<li><a class="show-love" href="https://wordpress.org/support/theme/consultstreet/reviews/#new-post" target="_blank"><i class="dashicons dashicons-smiley"></i><?php _e( 'Share a Good Review','consultstreet' ); ?> </a></li>
				</ul>
			</div>
		<?php
	   }
	}
	
	$wp_customize->add_setting(
		'pro_info_buttons',
		array(
		   'capability'     => 'edit_theme_options',
			'sanitize_callback' => 'consultstreet_sanitize_text',
		)	
	);
	
	$wp_customize->add_control( new ConsultStreet_WP_Button_Customize_Control( $wp_customize, 'pro_info_buttons', array(
		'section' => 'upgrade_premium',
    ))
);
}
add_action( 'customize_register', 'consultstreet_upgrade_pro_options' );