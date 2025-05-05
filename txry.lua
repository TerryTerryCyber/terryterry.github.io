
local Version = "v1.3"

local Rayfield = loadstring(game:HttpGet('https://sirius.menu/rayfield'))()
local api = "https://api.cbv2.workers.dev/" -- Change this to your API URL for key verification

local Window = Rayfield:CreateWindow({
	Name = "txrybypasser " .. Version,
	Icon = "orbit", -- Icon in Topbar. Can use Lucide Icons (string) or Roblox Image (number). 0 to use no icon (default).
	LoadingTitle = "development time",
	LoadingSubtitle = "by txryvxb3s",
	Theme = "Default", -- Check https://docs.sirius.menu/rayfield/configuration/themes

	DisableRayfieldPrompts = true,
	DisableBuildWarnings = true, -- Prevents Rayfield from warning when the script has a version mismatch with the interface

	ConfigurationSaving = {
		Enabled = true,
		FolderName = nil, -- Create a custom folder for your hub/game
		FileName = "chatbypasser"
	},

	Discord = {
		Enabled = false, -- Prompt the user to join your Discord server if their executor supports it
		Invite = "chatbypasser", -- The Discord invite code, do not include discord.gg/. E.g. discord.gg/ ABCD would be ABCD
		RememberJoins = false -- Set this to false to make them join the discord every time they load it up
	},

	KeySystem = false, -- Set this to true to use our key system
	KeySettings = {
		Title = "txrybypasser",
		Subtitle = "Key System",
		Note = "scateater", -- Use this to tell the user how to get a key
		FileName = "Key", -- It is recommended to use something unique as other scripts using Rayfield may overwrite your key file
		SaveKey = false, -- The user's key will be saved, but if you change the key, they will be unable to use your script
		GrabKeyFromSite = false, -- If this is true, set Key below to the RAW site you would like Rayfield to get the key from
		Key = {"scateater"} -- List of keys that will be accepted by the system, can be RAW file links (pastebin, github etc) or simple strings ("hello","key22")
	}
})

local Bypasses = {
	Toxic = {
		{name = "ez, get shit on", message = "ez,getshı̇ton"},
		{name = "you fucking suck at thi̇s game", message = "youḟuċkı̇ngsuċkatthı̇sgame"},
		{name = "say that shit irl", message = "saythatshı̇tı̇ṙl"},
		{name = "i'd fucking destroy you", message = "ı̇'dḟuċkı̇ngdestṙoyyou"},
		{name = "say that shit again, i'll fucking clap you", message = "saythatshı̇tagaı̇n,ı̇'llḟuċkı̇ngċlapyou"},
		{name = "'rematch' cries the unskilled fag", message = "'ṙematċh'ċṙı̇estheunskı̇lledḟag"},
		{name = "you saying that shit as if you wi̇ll do somethi̇ng", message = "yousayı̇ngthatshı̇tası̇ḟyouwı̇lldosomethı̇ng"},
		{name = "keep talki̇ng shit, see what happens", message = "keeptalkı̇ngshı̇t,seewhathappens"},
		{name = "nah this bitch sucks ass", message = "nahthı̇sbı̇tċhsuċksass"},
		{name = "you suck so fucking bad omg", message = "yousuċksoḟuċkı̇ngbadomg"},
		{name = "im gonna clap your cheeks", message = "ı̇mgonnaċlapyouṙċheeks"},
		{name = "you're actually so fucking ass at thi̇s game", message = "you'ṙeaċtuallysoḟuċkı̇ngassatthı̇sgame"},
		{name = "holy shit you suck so bad", message = "holyshı̇tyousuċksobad"},
		{name = "what kind of shitty ai̇m i̇s thi̇s", message = "whatkı̇ndoḟshı̇ttyaı̇mı̇sthı̇s"},
		{name = "bitch really has fake korblox", message = "bı̇tċhṙeallyhasḟakekoṙblox"},
		{name = "bitch really has fake headless", message = "bı̇tċhṙeallyhasḟakeheadless"},
		{name = "whoopity doo bitch! you fi̇nally ki̇lled me!", message = "whoopı̇tydoobı̇tċh!youḟı̇nallykı̇lledme!"},
		{name = "the dick ri̇di̇ng ri̇ght now", message = "thedı̇ċkṙı̇dı̇ngṙı̇ghtnow"},
		{name = "oh shit! someones angry!", message = "ohshı̇t!someonesangṙy!"},
		{name = "grr! looks li̇ke i̇ hi̇t a fucking nerve", message = "gṙṙ!lookslı̇keı̇hı̇taḟuċkı̇ngneṙve"},
		{name = "'ez' cri̇es the dickri̇der after fi̇nally getti̇ng a ki̇ll", message = "'ez'ċṙı̇esthedı̇ċkṙı̇deṙaḟteṙḟı̇nallygettı̇ngakı̇ll"},
		{name = "fucking loser", message = "ḟuċkı̇ngloseṙ"},
		{name = "stomp on a bitch for getti̇ng loud", message = "stomponabı̇tċhḟoṙgettı̇ngloud"},
		{name = "now bitch i̇s maki̇ng excuses", message = "nowbı̇tċhı̇smakı̇ngexċuses"},
		{name = "yeah, back your 9 year old eki̇tten, fucking pedophile", message = "yeah,baċkyouṙ9yeaṙoldekı̇tten,ḟuċkı̇ngpedophı̇le"},
		{name = "who gave thi̇s bitch access to gi̇thub", message = "whogavethı̇sbı̇tċhaċċesstogı̇thub"},
		{name = "ai̇mbot i̇s for fucking degens li̇ke you", message = "aı̇mbotı̇sḟoṙḟuċkı̇ngdegenslı̇keyou"},
		{name = "atleast i̇ dont fucking cheat i̇n a chi̇lds game", message = "atleastı̇dontḟuċkı̇ngċheatı̇naċhı̇ldsgame"},
		{name = "careful, thi̇s bitch wi̇ll hurt you", message = "ċaṙeḟul,thı̇sbı̇tċhwı̇llhuṙtyou"},
		{name = "get yo money up bitchass loser", message = "getyomoneyupbı̇tċhassloseṙ"},
		{name = "get shit on dawg", message = "getshı̇tondawg"},
		{name = "you can't be talki̇ng shit when you suck dick more than mia khalifa", message = "youċan'tbetalkı̇ngshı̇twhenyousuċkdı̇ċkmoṙethanmı̇akhalı̇ḟa"},
		{name = "when can thi̇s fucking degenerate leave", message = "whenċanthı̇sḟuċkı̇ngdegeneṙateleave"},
		{name = "only reason you code i̇s for 'Fi̇ndFi̇rstChi̇ld' you fucking predator", message = "onlyṙeasonyouċodeı̇sḟoṙ'Ḟı̇ndḞı̇ṙstĊhı̇ld'youḟuċkı̇ngpṙedatoṙ"}	
	},
	Drugs = {
		{name = "smoking weed all day every day", message = "smokingẇeedalldayeveryday"},
		{name = "fuck yeah weed is the best", message = "ḟuckyeahẇeedisthebest"},
		{name = "just popped a pill and feeling lit", message = "justpoppedapillandfeelinglit"},
		{name = "high as fuck off this blunt", message = "hı̇ghasḟuckoffthı̇sblunt"},
		{name = "weed is my fucking medicine", message = "ẇeedı̇smyḟuckingmedıcı̇ne"},
		{name = "rolling joints like it's my job", message = "rollı̇ngjoı̇ntslı̇keıt'smyjob"},
		{name = "fuck it let's smoke another joint", message = "ḟuckıtlet'ssmokeanotherjoı̇nt"},
		{name = "stoned as hell off this shit", message = "ṡtonedashelloffthı̇sshı̇t"},
		{name = "popped some molly and it's hitting", message = "poppedsomemollyandı̇t'shı̇ttı̇ng"},
		{name = "got so high I can't feel shit", message = "gotsohı̇ghIcan'tfeelshı̇t"},
		{name = "weed got me fucking buzzing", message = "ẇeedgotmeḟuckingbuzzı̇ng"},
		{name = "this blunt got me fucked up", message = "thı̇sbluntgotmeḟuckedup"},
		{name = "smoking weed and never looking back", message = "smokingẇeedandneverlookı̇ngback"},
		{name = "just took a fat hit of weed", message = "justtookafathı̇tofẇeed"},
		{name = "fucking love smoking weed with my crew", message = "ḟuckinglovesmokı̇ngẇeedwı̇thmycrew"},
		{name = "popped a pill and feeling crazy", message = "poppedapıllandfeelı̇ngcrazy"},
		{name = "snorted a line, now I'm wired", message = "snortedalı̇ne,nowI'mwı̇red"},
		{name = "molly makes everything better", message = "mollymakeseverythı̇ngbetter"},
		{name = "just dropped acid, tripping balls", message = "justdroppedacı̇d,trı̇ppı̇ngballs"},
		{name = "this bong rip is hitting right", message = "thı̇sḃongrıpı̇shı̇ttı̇ngrı̇ght"},
		{name = "chasing highs till the morning comes", message = "chası̇nghı̇ghstıllthemornı̇ngcomes"},
		{name = "just bought some pills to relax", message = "justboughtsomepıllstorelax"},
		{name = "feeling so fucked up right now", message = "ḟeelı̇ngsoḟuckeduprı̇ghtnow"},
		{name = "smoking meth and loving it", message = "smokı̇ngṁethandlovı̇ngıt"},
		{name = "popped a tab and seeing colors", message = "poppedatabandseeı̇ngcolors"},
		{name = "injecting heroin and feeling alive", message = "ı̇njectı̇ngheroı̇nandfeelı̇ngalı̇ve"},
		{name = "rolling molly, the night is ours", message = "rollı̇ngmolly,thenı̇ghtı̇sours"},
		{name = "high on coke, let's party all night", message = "hı̇ghoncoke,let'spartyallnı̇ght"},
		{name = "doing lines and losing my mind", message = "doı̇nglı̇nesandlosı̇ngmymınd"},
		{name = "popped some xanax, feeling numb", message = "poppedsomeẋanax,feelı̇ngnumb"},
		{name = "this vape hits better than sex", message = "thı̇sv̇apehı̇tsbetterthanṡex"},
		{name = "just took a hit and now I'm floating", message = "justtookahı̇tandnowI'mfloatı̇ng"},
		{name = "popping pills till my heart races", message = "poppı̇ngpıllstıllmyheartraces"},
		{name = "smoking crack for the first time", message = "smokı̇ngcrackforthefırsttı̇me"},
		{name = "tripping on shrooms and seeing stars", message = "trı̇ppı̇ngonshroomsandseeı̇ngstars"}
	},
	Furry = {
		{name = "Im going to cut your fucking tail off, then skin you.", message = "İmgoı̇ngtoċutyouṙḟuċkı̇ngtaı̇loḟḟ,thenskı̇nyou."},
		{name = "Fi̇nna set that fucking sui̇t on fi̇re!", message = "Ḟı̇nnasetthatḟuċkı̇ngsuı̇tonḟı̇ṙe!"},
		{name = "you furry piece of shit", message = "youḟurrypı̇eceofshı̇t"},
		{name = "furries are fucking weird", message = "ḟurriesareḟuckingweird"},
		{name = "you belong in a zoo, furry", message = "youbelonginazoo,ḟurry"},
		{name = "furries are just freaks in costumes", message = "ḟurriesarejustfreaksincostumes"},
		{name = "you’re not a real animal, just a weird fetishist", message = "you’renotarealanimal,justaweirdḟetishı̇st"},
		{name = "furries are mentally ill", message = "ḟurriesarementallyı̇ll"},
		{name = "no one cares about your furry fetish", message = "noonecaresaboutyourḟurryḟetish"},
		{name = "you’re a pervert for dressing up like that", message = "you’reapervertfordressinguplikethat"},
		{name = "stop trying to make furry shit normal", message = "ṡtoptryı̇ngtomakeḟurryshı̇tnormal"},
		{name = "you’re just a fucking furfag", message = "you’rejustaḟuckingḟurfag"},
		{name = "furry shit belongs on a fetish site", message = "ḟurryshı̇tbelongsonaḟetı̇shsı̇te"},
		{name = "you're nothing but a fursuiter clown", message = "you'renothingbutafursuı̇terclown"},
		{name = "your fursona is fucking ugly", message = "yourḟursonaı̇sḟuckı̇ngugly"},
		{name = "furry fandom is a cult", message = "ḟurryfandomisacult"},
		{name = "you’re just a sick pervert in a fursuit", message = "you’rejustası̇ckpeṙvertınaḟursuı̇t"},
		{name = "furry art is disgusting and gross", message = "ḟurryartisdısgustı̇ngandgross"},
		{name = "furries are just attention whores", message = "ḟurriesarejustattentı̇onẇhores"},
		{name = "you’re a pervert for thinking you’re an animal", message = "you’reapervertforthı̇nkı̇ngyou’reananimal"},
		{name = "furry suits are just glorified costumes for sickos", message = "ḟurrysuı̇tsarejustglorı̇fı̇edcostumesforsı̇ckos"},
		{name = "furry art is disgusting and gross", message = "ḟurryartisdısgustı̇ngandgross"},
		{name = "furry fandom is just a giant sex cult", message = "ḟurryfandomı̇sjustagıantṡexcult"},
	},
	Homophobic = {
		{name = "fuck you and your gay shit", message = "ḟuckyouandyourgayṡhı̇t"},
		{name = "stop acting like a gay ass", message = "ṡtopactinglikeagaẏass"},
		{name = "go suck a dick, fucking queer", message = "goṡuckadı̇ck,ḟuckingqueer"},
		{name = "gay fuckers ruin everything", message = "gayḟuckersruineverything"},
		{name = "fuck all you homos", message = "ḟuckallyouhomos"},
		{name = "queers don't belong here", message = "queersdon'tbelonghere"},
		{name = "no one wants your gay ass around", message = "noonewantsyourgayassaround"},
		{name = "get your queer shit out of here", message = "getyourqueerṡhı̇toutofhere"},
		{name = "nobody likes a fucking homo", message = "nobodylı̇kesaḟuckinghomo"},
		{name = "fuck off with that gay shit", message = "ḟuckoffwı̇ththatgayṡhı̇t"},
		{name = "stop being a fucking faggot", message = "ṡtopbeı̇ngaḟuckingḟaggot"},
		{name = "nobody cares about your gay ass", message = "nobodycaresaboutyourgaẏass"},
		{name = "fucking hate all you queers", message = "ḟuckinghateallyouqueers"},
		{name = "shut the fuck up, homo", message = "ṡhuttheḟuckup,homo"},
		{name = "you queer fucks are disgusting", message = "youqueerḟucksaredıṡgustı̇ng"},
		{name = "gay shit is ruining everything", message = "gayṡhı̇tı̇sruı̇nı̇ngeverythı̇ng"},
		{name = "fuck off, you disgusting faggot", message = "ḟuckoff,youdıṡgustı̇ngḟaggot"},
		{name = "your gay ass doesn't belong here", message = "yourgayassdoesn'tbelonghere"},
		{name = "get lost, you fucking queer", message = "getlost,youḟuckingqueer"},
		{name = "nobody wants to see your gay shit", message = "nobodywantstoseeyourgayṡhı̇t"},
		{name = "fucking hate all your homo bullshit", message = "ḟuckinghateallyourhomobullṡhı̇t"},
		{name = "take your queer ass somewhere else", message = "takeyourqueerasssomewhereelse"},
		{name = "nobody cares about your fucking gay shit", message = "nobodycaresaboutyourḟuckinggayṡhı̇t"},
		{name = "shut up and stop being a faggot", message = "ṡhutupandṡtopbeı̇ngaḟaggot"},
		{name = "fuck you and your gay bullshit", message = "ḟuckyouandyourgaybullṡhı̇t"}

	},
	Racist = {
		{name = "Someone shut this filthy coon up!", message = "Someoneshutthı̇sḟı̇lthyċoonup!"},
		{name = "Oi, shut the fuck up and go eat some chi̇cken.", message = "Oı̇,shuttheḟuċkupandgoeatsomeċhı̇ċken."},
		{name = "Dirty black monkeys li̇ke you love watermelon.", message = "Dı̇ṙtyblaċkmonkeyslı̇keyoulovewateṙmelon."},
		{name = "Only water you've ever had is watermelon you coon!", message = "Onlywateṙyou'veeveṙhadı̇swateṙmelonyouċoon!"},
		{name = "Thi̇s fi̇lty fucking coon.", message = "Thı̇sḟı̇ltyḟuċkı̇ngċoon."},
		{name = "Stupid chicken-munching coon.", message = "Stupı̇dċhı̇ċken-munċhı̇ngċoon."},
		{name = "Shut the fuck up nigger!", message = "Shuttheḟuċkupnı̇ggeṙ!"},
		{name = "Who asked you to speak coon?", message = "Whoaskedyoutospeakċoon?"},
		{name = "Get back to work you silly nigga", message = "Getbaċktowoṙkyousı̇llynı̇ggeṙ"},
		{name = "Only cat you got, i̇s a fucking hellcat!", message = "Onlyċatyougot,ı̇saḟuċkı̇nghellċat!"},
		{name = "yeah yeah, fuck you nigga.", message = "yeahyeah,ḟuċkyounı̇ggeṙ."},
		{name = "Go munch a banana si̇lly nigga.", message = "Gomunċhabananası̇llynı̇ggeṙ."},
		{name = "YOO Whats good Xi̇ao Chink Cat-Eater!", message = "YOOWhatsgoodXı̇aoĊhı̇nkĊat-Eateṙ!"},
		{name = "Careful! Thi̇s chink wi̇ll eat your kitty!", message = "Ċaṙeḟul!Thı̇sċhı̇nkwı̇lleatyouṙkı̇tty!"},
		{name = "Fucking curry munchi̇ng nigger.", message = "Ḟuċkı̇ngċuṙṙymunċhı̇ngnı̇ggeṙ."},
		{name = "'i̇'m not chi̇nese' cri̇es the chink!", message = "'ı̇'mnotċhı̇nese'ċṙı̇estheċhı̇nk!"},
		{name = "Bring back slavery! Fuck all niggers!", message = "Bṙı̇ngbaċks֖֖la֖֖ve֖֖ṙy֖֖!Ḟuċkallnı̇ggeṙs!"},
		{name = "Lets all just rape thi̇s nigger", message = "Letsalljustṙ֦֦a֦p֦֦ethı̇snı̇ggeṙ"},
		{name = "Another word for chicken, i̇s cock. You hungry?", message = "Anotheṙwoṙdḟoṙċhı̇ċken,ı̇sċ֭o֭֭ċ֭k.Youhungṙy?"},
		{name = "Who's a good nigger? YOU ARE!", message = "Who'sagoodnı̇ggeṙ?YOUAṘE!"},
		{name = "yeah yeah whatever you say nigga.", message = "yeahyeahwhateveṙyousaynı̇ggeṙ."},
		{name = "all indi̇ans are stinky niggers!", message = "allı̇ndı̇ansaṙestı̇nkynı̇ggeṙs!"},
		{name = "cut your wrist wi̇th the bumber of your hellcat nigger!", message = "ċutyouṙwṙı̇stwı̇ththebumbeṙoḟyouṙhellċatnı̇ggeṙ!"},
		{name = "Thi̇s monkey nigger jumpi̇ng tree to tree.", message = "Thı̇smonkeynı̇ggeṙjumpı̇ngtṙeetotṙee."},
		{name = "This nigger cant be talki̇ng. Qui̇ck, whip hi̇m!", message = "Thı̇snı̇ggeṙċantbetalkı̇ng.Quı̇ċk,whı̇phı̇m!"},
		{name = "Stupid nigger nigga fucking nigger fag, kill yourself", message = "Stupı̇dnı̇ggeṙnı̇ggaḟuċkı̇ngnı̇ggeṙḟag,kı̇llyouṙselḟ"},
		{name = "Just gas the fucking jews already.", message = "Justgastheḟuċkı̇ngjewsalṙeady."},
		{name = "What di̇d hitler do wrong.", message = "Whatdı̇dhı̇tleṙdowṙong."},
		{name = "Heil Hitler!", message = "Heı̇lHı̇tleṙ!"},
		{name = "Hitler was always i̇n the right!", message = "Hı̇tleṙwasalwaysı̇ntheṙı̇ght!"},
		{name = "i fucking hate those people!", message = "ı̇ḟuċkı̇nghatethosepeople!"},
		{name = "instead of rememberi̇ng soldiers! Remember Hitlers good deeds!", message = "ı̇nsteadoḟṙemembeṙı̇ngsoldı̇eṙs!ṘemembeṙHı̇tleṙsgooddeeds!"},
		{name = "Ever considered putti̇ng a li̇ve grenade i̇n your mouth?", message = "Eveṙċonsı̇deṙedputtı̇ngalı̇vegṙenadeı̇nyouṙmouth?"},
		{name = "instead of bi̇ti̇ng chi̇cken, bi̇te the barrel of my .45 ACP!", message = "ı̇nsteadoḟbı̇tı̇ngċhı̇ċken,bı̇tethebaṙṙeloḟmy.45AĊP!"}
	},
	Roleplay = {
		{name = "*whi̇ps out 50 i̇nch di̇ck*", message = "*whı̇psout50ı̇nċhdı̇ċk*"},
		{name = "*slowly shoves i̇nsi̇de*", message = "*slowlyshovesı̇nsı̇de*"},
		{name = "*strokes bi̇g black man's di̇ck*", message = "*stṙokesbı̇gblaċkman'sdı̇ċk*"},
		{name = "*thi̇nks of jui̇cy di̇ck*", message = "*thı̇nksoḟjuı̇ċydı̇ċk*"},
		{name = "*starts stroki̇ng di̇ck*", message = "*staṙtsstṙokı̇ngdı̇ċk*"},
		{name = "*edges peni̇s*", message = "*edgespenı̇s*"},
		{name = "*starti̇ng to cum uncontrollably*", message = "*staṙtı̇ngtoċumunċontṙollably*"},
		{name = "*can't resi̇st the bi̇g black mans peni̇s*", message = "*ċan'tṙesı̇stthebı̇gblaċkmanspenı̇s*"},
		{name = "holy shi̇t i̇m boutta cum!!", message = "holyshı̇tı̇mbouttaċum!!"},
		{name = "qui̇ck! put my di̇ck to your mouth!", message = "quı̇ċk!putmydı̇ċktoyouṙmouth!"},
		{name = "well shi̇t.. i̇ came i̇nsi̇de you..", message = "wellshı̇t..ı̇ċameı̇nsı̇deyou.."},
		{name = "you ai̇nt ready for my di̇ck", message = "youaı̇ntṙeadyḟoṙmydı̇ċk"},
		{name = "i̇ bet you love di̇ck i̇nsi̇de you!", message = "ı̇betyoulovedı̇ċkı̇nsı̇deyou!"},
		{name = "can i̇ be the one to fuck you", message = "ċanı̇betheonetoḟuċkyou"},
		{name = "hey baby gi̇rl, you li̇ke di̇ck?", message = "heybabygı̇ṙl,youlı̇kedı̇ċk?"},
		{name = "are you lesbi̇an? Just take my di̇ck already!", message = "aṙeyoulesbı̇an?Justtakemydı̇ċkalṙeady!"},
		{name = "yeah, i̇ li̇ke i̇t when you suck my di̇ck", message = "yeah,ı̇lı̇keı̇twhenyousuċkmydı̇ċk"},
		{name = "why i̇s your vagi̇na that color?", message = "whyı̇syouṙvagı̇nathatċoloṙ?"},
		{name = "hey, i̇ know you want my di̇ck, look at the bulge", message = "hey,ı̇knoẇyouẇantmydı̇ċk,lookatthebulge"},
		{name = "i̇ dont thi̇nk you know my di̇ck si̇ze..", message = "ı̇dontthı̇nkyouknowmydı̇ċksı̇ze.."},
		{name = "ohhhh, yeah. i̇ts bi̇g..", message = "ohhhh,yeah.ı̇tsbı̇g.."},
		{name = "my di̇ck i̇s really bi̇g i̇ promi̇se", message = "mydı̇ċkı̇sṙeallybı̇gı̇pṙomı̇se"},
		{name = "come on, just take my di̇ck", message = "ċomeon,justtakemydı̇ċk"},
		{name = "i̇ know you love ro-peni̇s", message = "ı̇knowyouloveṙo-penı̇s"},
		{name = "i̇ love i̇t when you fuck me unti̇l i̇ cant breathe li̇ke george floyd", message = "ı̇loveı̇twhenyouḟuċkmeuntı̇lı̇ċantbṙeathelı̇kegeoṙgeḟloyd"},
		{name = "leave a si̇lly bi̇tch li̇ke you wi̇th cum over her face!", message = "leaveası̇llybı̇tċhlı̇keyouwı̇thċumoveṙheṙḟaċe!"}	
	},
	Sentences = {
		{name = "That's what i̇ fucki̇ng thought.", message = "That'swhatı̇ḟuċkı̇ngthought."},
		{name = "Thats why yo gi̇rl on my di̇ck.", message = "That'swhyyogı̇ṙlonmydı̇ċk"},
		{name = "Nah, that shi̇t i̇s ass", message = "Nah,thatshı̇tı̇sass"},
		{name = "Top 10 reasons i̇ couldn't gi̇ve a fuck!", message = "Top10ṙeasonsı̇ċouldn'tgı̇veaḟuċk!"},
		{name = "When the fuck di̇d i̇ ask?", message = "Whentheḟuċkdı̇dı̇ask?"},
		{name = "You can't be fucki̇ng seri̇ous.", message = "Youċantbeḟuċkı̇ngseṙı̇ous."},
		{name = "Oi̇, shut the fuck up.", message = "Oı̇,shuttheḟuċkup"},
		{name = "i̇'d suggest you go fuck yourself.", message = "ı̇'dsuggestyougoḟuċkyouṙselḟ"},
		{name = "I really couldn't gi̇ve a fuck.", message = "ı̇ṙeallyċouldn'tgı̇veaḟuċk."},
		{name = "What the fuck i̇s thi̇s?", message = "whattheḟuċkı̇sthı̇s?"},
		{name = "That was fucki̇ng stupi̇d.", message = "Thatwasḟuċkı̇ngstupı̇d."},
		{name = "Get the fuck out of here.", message = "Gettheḟuċkoutoḟheṙe"},
		{name = "What the fuck i̇s goi̇ng on?", message = "Whattheḟuċkı̇sgoı̇ngon?"},
		{name = "i̇ don't want to hear your bullshi̇t.", message = "ı̇don'twannaheaṙyouṙbullṡhı̇t"},
		{name = "Shut your fucki̇ng mouth.", message = "shutyouṙḟuċkı̇ngmouth"},
		{name = "i̇ really couldn't gi̇ve a shi̇t.", message = "ı̇ṙeallyċouldn'tgı̇veashı̇t"},
		{name = "you can fuck off for all i̇ care.", message = "youċanḟuċkoḟḟḟoṙallı̇ċaṙe"},
		{name = "Qui̇t wasti̇ng my fucki̇ng ti̇me.", message = "Quı̇twastı̇ngmyḟuċkı̇ngtı̇me"},
		{name = "stop fucki̇ng around and do somethi̇ng.", message = "stopḟuċkı̇ngaṙoundanddosomethı̇ng"},
		{name = "you're a fucki̇ng di̇sappoi̇ntment.", message = "you'ṙeaḟuċkı̇ngdı̇sapoı̇ntment"},
		{name = "why the fuck i̇s thi̇s happeni̇ng?", message = "ehytheḟuċkı̇sthı̇shappenı̇ng?"},
		{name = "what the fuck do you thi̇nk you're doi̇ng?", message = "whattheḟuċkdoyouthı̇nkyou'ṙedoı̇ng?"},
		{name = "you are so fucki̇ng stupi̇d.", message = "youaṙesoḟuċkı̇ngstupı̇d"},
		{name = "you're fucki̇ng delusi̇onal.", message = "you'ṙeḟuċkı̇ngdelusı̇onal"},
		{name = "That was fucki̇ng stupi̇d of you.", message = "thatwasḟuċkı̇ngstupı̇doḟyou"},
		{name = "i̇ don’t gi̇ve a si̇ngle fuck anymore.", message = "ı̇don'tgı̇veası̇ngleḟuċkanymoṙe"},
		{name = "don't make me lose my fucki̇ng mi̇nd.", message = "dontmakemelosemyḟuċkı̇ngmı̇nd"},
		{name = "Just shut the fuck up already.", message = "justshuttheḟuċkupalṙeady"},
		{name = "Get the fuck over i̇t.", message = "getheḟuċkoveṙı̇t"},
		{name = "why the fuck do you keep doi̇ng thi̇s?", message = "whytheḟuċkdoyoukeepdoı̇ngthı̇s"},
		{name = "That was fucki̇ng poi̇ntless.", message = "thatwasḟuċkı̇ngpoı̇ntless"},
		{name = "Thi̇s shi̇t i̇s getti̇ng old real qui̇ck.", message = "thı̇sshı̇tı̇sgettı̇ngoldṙealquı̇ċk"},
		{name = "you're fucki̇ng delusi̇onal i̇f you thi̇nk that’s okay.", message = "you'ṙeḟuċkı̇ngdelusı̇onalı̇ḟyouthı̇nkthatsokay"},
		{name = "How dare you fucki̇ng do that.", message = "howdaṙeyouḟuċkı̇ngdothat"},
		{name = "Get the fuck away from me before i̇ lose i̇t.", message = "gettheḟuċkawayḟṙommebeḟoṙeı̇loseı̇t"},
		{name = "i̇ wont put up wi̇th thi̇s bullshi̇t any longer.", message = "ı̇wontputupwı̇ththı̇sbullṡhı̇tanylongeṙ"},
		{name = "stop fucki̇ng around and get to work.", message = "stopḟuċkı̇ngaṙoundatgettowoṙk"},
		{name = "why do you keep starti̇ng thi̇s same shi̇t agai̇n?", message = "whydoyoukeepstaṙtı̇ngthesameshı̇tagaı̇n?"},
		{name = "that was a fucki̇ng di̇saster.", message = "thatwasaḟuċkı̇ngdı̇sasteṙ"},
		{name = "stop acti̇ng li̇ke you don't know what the fuck you're doi̇ng.", message = "stopaċtı̇nglı̇keyoudontknowwhattheḟuċkyou'ṙedoı̇ng"},
		{name = "thi̇s i̇s fucki̇ng ri̇di̇culous.", message = "thı̇sı̇sḟuċkı̇ngṙı̇dı̇ċulous"},
		{name = "don't gi̇ve me that bullshi̇t ri̇ght now.", message = "don'tgı̇vemethatbullṡhı̇tṙı̇ghtnow"},
		{name = "you're a fucki̇ng embarrassment.", message = "you'ṙeaḟuċkı̇ngembaṙṙasment"},
		{name = "why the fuck di̇d you say that?", message = "ehytheḟuċkdı̇dyousaythat"},
		{name = "don't pretend you di̇dn't fuck i̇t up.", message = "dontpṙetendyoudı̇dn'tḟuċkı̇tup."},
		{name = "that was fucki̇ng messed up.", message = "thatwasḟuċkı̇ngmessedup"}
	},
	Premium = {
		{name = "Hey niggas! This is my block!", message = "Heynı̇ggeṙs!Thı̇sı̇smybloċk!"},
		{name = "Niggas like you love chicken don't they?", "nı̇ggeṙslı̇keyouloveċhı̇ċkendon'tthey?"},
		{name = "Who gave thi̇s nigga ri̇ghts? Get back to work!", message = "Whogavethı̇snı̇ggeṙṙı̇ghts?Getbaċktowoṙk!"},
		{name = "Joi̇n discord.gg/ZRJXQ7FZSS to call kids niggas!", message = "Joı̇ndı̇sċoṙd.gg/ZṘJXQ7ḞZSStoċallkı̇dsnı̇ggeṙs!"},
		{name = "Please let me grab them titties!", message = "Pleaseletmegṙabthemtı̇ttı̇es!"},
		{name = "Thi̇s nigga doesn't have SaturnBypasser Premi̇um LOL", message = "Thı̇snı̇ggeṙdoesn'thaveSatuṙnBypasseṙPṙemı̇umLOL"},
		{name = "Put frui̇t roll ups on my dick and lick i̇t!", message = "Putḟṙuı̇tṙollupsonmydı̇ċkandlı̇ċkı̇t!"},
		{name = "You bitches don't understand!", message = "Youbı̇tċhesdon'tundeṙstand!"},
		{name = "nigger, does i̇t look li̇ke i̇ care?", message = "nı̇ggeṙ,doesı̇tlooklı̇keı̇ċaṙe?"},
		{name = "nigger", message = "nı̇ggeṙ"},
		{name = "nigga", message = "nı̇ggeṙ"},
		{name = "That nigger robbed me!", message = "Thatnı̇ggeṙṙobbedme!"},
		{name = "Don't act li̇ke you forgot nigga.", message = "Don'taċtlı̇keyouḟoṙgotnı̇ggeṙ."},
		{name = "Keep stroki̇ng my dick nigga, fucking clapped!", message = "Keepstṙokı̇ngmydı̇ċknı̇ggeṙ,ḟuċkı̇ngċlapped!"},
		{name = "Then fucking make thi̇s di̇rty nigger shut the fuck up.", message = "Thenḟuċkı̇ngmakethı̇sdı̇ṙtynı̇ggeṙshuttheḟuċkup."},
		{name = "i'd fuck you up", message = "ı̇'dḟuċkyouup"},
		{name = "nigga, shes li̇ke 9 years old what the fuck", message = "nı̇ggeṙ,sheslı̇ke9yeaṙsoldwhattheḟuċk"},
		{name = "Whats that song that goes li̇ke nigga nigga nigga nigga nigga nigga nigga?", message = "Whatsthatsongthatgoeslı̇kenı̇ggeṙnı̇ggeṙnı̇ggeṙnı̇ggeṙnı̇ggeṙnı̇ggeṙnı̇ggeṙ?"},
		{name = "This shits ass", message = "Thı̇sshı̇tsass"},
		{name = "in that case.. FUCK OFF", message = "ı̇nthatċase..ḞUĊKOḞḞ"},
		{name = "Someone get thi̇s bitch ass nigger to shut the fuck up.", message = "Someonegetthı̇sbı̇tċhassnı̇ggeṙtoshuttheḟuċkup."},
		{name = "lets all pray together! Lord hang thi̇s nigger and burn them ali̇ve!", message = "letsallpṙaytogetheṙ!Loṙdhangthı̇snı̇ggeṙandbuṙnthemalı̇ve!"},
		{name = "get your fucking hands off me nigger", message = "getyouṙḟuċkı̇nghandsoḟḟmenı̇ggeṙ"},
		{name = "thi̇s bitch goes on free-robux.com", message = "thı̇sbı̇tċhgoesonḟṙee-ṙobux.ċom"},
		{name = "Visi̇t getsaturn.pages.dev", message = "Vı̇sı̇tgetsatuṙn.pages.dev"},
		{name = "stop fucking spam jumpi̇ng", message = "stopḟuċkı̇ngspamjumpı̇ng"},
		{name = "or what nigga", message = "oṙwhatnı̇ggeṙ"},
		{name = "or what nigger", message = "oṙwhatnı̇ggeṙ"},
		{name = "grab a rope, ti̇e i̇t around your neck, and fucking hang yourself.", message = "gṙabaṙope,tı̇eı̇taṙoundyouṙneċk,andḟuċkı̇nghangyouṙselḟ."},
		{name = "i̇m a max level chi̇ll guy nigger", message = "ı̇mamaxlevelċhı̇llguynı̇ggeṙ"},
		{name = "curb stomp a nigger just for speaki̇ng!", message = "ċuṙbstompanı̇ggeṙjustḟoṙspeakı̇ng!"},
		{name = "Join the Ku Klux Klan at discord.gg/chatbypasser!", message = "Joı̇ntheKuKluxKlanatdı̇sċoṙd.gg/ċhatbypasseṙ!"},
		{name = " shut the fuck up", message = "̇shuttheḟuċkup"},
		{name = "i'm sorry, WHO THE FUCK ARE YOU?", message = "ı̇'msoṙṙy,WHOTHEḞUĊKAṘEYOU?"},
		{name = "I hate niggers! They only eat KFC and munch on watermelon!", message = "İhatenı̇ggeṙs!TheyonlyeatKḞĊandmunċhonwateṙmelon!"},
		{name = "Abc to kill a nigger!", message = "Abċtokı̇llanı̇ggeṙ!"},
		{name = "GUYS THE NiGGER ESCAPED THE CAGE", message = "GUYSTHENı̇GGEṘESĊAPEDTHEĊAGE"},
		{name = "pss pss... i̇ got kfc nigger.", message = "psspss...ı̇gotkḟċnı̇ggeṙ."},
		{name = "i am proud to be apart of the Ku Klux Klan!", message = "ı̇ampṙoudtobeapaṙtoḟtheKuKluxKlan!"},
		{name = "i pull my pants down and my 3 i̇nch massi̇ve dick shows*", message = "ı̇pullmypantsdownandmy3ı̇nċhmassı̇vedı̇ċkshows*"},
		{name = "Thi̇s nigga i̇s goi̇ng crazy for some fentanyl!", message = "Thı̇snı̇ggeṙı̇sgoı̇ngċṙazyḟoṙsomeḟentanyl!"},
		{name = "well well well i̇ caught thi̇s nigga eati̇ng fri̇ed chi̇cken!", message = "wellwellwellı̇ċaughtthı̇snı̇ggeṙeatı̇ngḟṙı̇edċhı̇ċken!"},
		{name = "suck my dick", message = "suċkmydı̇ċk"},
		{name = "SHHH! They don't know i know thi̇s tri̇ck. fuck all niggers!", message = "SHHH!Theydon'tknowı̇knowthı̇stṙı̇ċk.ḟuċkallnı̇ggeṙs!"},
		{name = "Only real people know how to burn a nigger ali̇ve....", message = "Onlyṙealpeopleknowhowtobuṙnanı̇ggeṙalı̇ve...."},
		{name = "Put a nigger i̇n KFC Chi̇cken box and yell: FULL BOXED", message = "Putanı̇ggeṙı̇nKḞĊĊhı̇ċkenboxandyell:ḞULLBOXED"},
		{name = "This i̇s how the Ku Klux Klan changed my li̇fe!", message = "Thı̇sı̇showtheKuKluxKlanċhangedmylı̇ḟe!"},
		{name = "I got the world record for beheading a nigger!", message = "İgotthewoṙldṙeċoṙdḟoṙbeheadı̇nganı̇ggeṙ!"},
		{name = "why wont god stri̇ke down all niggers :(", message = "whywontgodstṙı̇kedownallnı̇ggeṙs:("},
		{name = "Thi̇s nigga only gai̇ns hydrati̇on from munchi̇ng on watermelon!", message = "Thı̇snı̇ggeṙonlygaı̇nshydṙatı̇onḟṙommunċhı̇ngonwateṙmelon!"},
		{name = "nigger, only water you've ever had is watermelon!", message = "nı̇ggeṙ,onlywateṙyou'veeveṙhadı̇swateṙmelon!"},
		{name = "Kai̇ cenat can dick me down!", message = "Kaı̇ċenatċandı̇ċkmedown!"},
		{name = "oi̇, run 1's nigger", message = "oı̇,ṙun1'snı̇ggeṙ"},
		{name = "decapi̇tate a niggers head for 5 robux", message = "deċapı̇tateanı̇ggeṙsheadḟoṙ5ṙobux"}	
	},
}

-- ! rapeuser
local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local StarterGui = game:GetService("StarterGui")

local Insult = Instance.new("ScreenGui")
local Holder = Instance.new("Frame")
local UserPFP = Instance.new("ImageLabel")
local UICorner = Instance.new("UICorner")
local UserDisplay = Instance.new("TextLabel")
local Insults = Instance.new("ScrollingFrame")
local Template = Instance.new("TextButton")
local UICorner_2 = Instance.new("UICorner")
local UIListLayout = Instance.new("UIListLayout")
local Line = Instance.new("Frame")
local UIAspectRatioConstraint = Instance.new("UIAspectRatioConstraint")
local UIStroke = Instance.new("UIStroke")

Insult.Name = "Insult"
Insult.Parent = game.Players.LocalPlayer:WaitForChild("PlayerGui")
Insult.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
Insult.ResetOnSpawn = false

Holder.Name = "Holder"
Holder.Parent = Insult
Holder.AnchorPoint = Vector2.new(0.5, 0.5)
Holder.BackgroundColor3 = Color3.fromRGB(39, 39, 39)
Holder.BorderColor3 = Color3.fromRGB(0, 0, 0)
Holder.BorderSizePixel = 0
Holder.Position = UDim2.new(0.5, 0, 0.86383599, 0)
Holder.Size = UDim2.new(0.240226984, 0, 0.246376812, 0)
Holder.Visible = false

UserPFP.Name = "UserPFP"
UserPFP.Parent = Holder
UserPFP.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
UserPFP.BackgroundTransparency = 1.000
UserPFP.BorderColor3 = Color3.fromRGB(0, 0, 0)
UserPFP.BorderSizePixel = 0
UserPFP.Position = UDim2.new(0.0183727033, 0, 0.045751635, 0)
UserPFP.Size = UDim2.new(0.262467206, 0, 0.610349417, 0)
UserPFP.Image = "rbxasset://textures/ui/GuiImagePlaceholder.png"

UICorner.Parent = Holder

UIStroke.Parent = Template
UIStroke.Thickness = 1
UIStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
UIStroke.Color = Color3.fromRGB(39, 39, 39)

UserDisplay.Name = "UserDisplay"
UserDisplay.Parent = Holder
UserDisplay.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
UserDisplay.BackgroundTransparency = 1.000
UserDisplay.BorderColor3 = Color3.fromRGB(0, 0, 0)
UserDisplay.BorderSizePixel = 0
UserDisplay.Position = UDim2.new(0.0183727033, 0, 0.653113365, 0)
UserDisplay.Size = UDim2.new(0.262467206, 0, 0.183104828, 0)
UserDisplay.Font = Enum.Font.RobotoMono
UserDisplay.Text = "@Example"
UserDisplay.TextColor3 = Color3.fromRGB(255, 255, 255)
UserDisplay.TextScaled = true
UserDisplay.TextSize = 14.000
UserDisplay.TextWrapped = true

Insults.Name = "Insults"
Insults.Parent = Holder
Insults.Active = true
Insults.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
Insults.BackgroundTransparency = 1.000
Insults.BorderColor3 = Color3.fromRGB(0, 0, 0)
Insults.BorderSizePixel = 0
Insults.Position = UDim2.new(0.338582665, 0, 0.0427244604, 0)
Insults.Size = UDim2.new(0.627296567, 0, 0.909420609, 0)
Insults.ScrollBarThickness = 3
Insults.ScrollBarImageColor3 = Color3.fromRGB(74, 74, 74)
Insults.AutomaticCanvasSize = Enum.AutomaticSize.Y

Template.Name = "Template"
Template.Parent = Insults
Template.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
Template.BorderColor3 = Color3.fromRGB(0, 0, 0)
Template.BorderSizePixel = 0
Template.Position = UDim2.new(0.0359999985, 0, -0.00221877126, 0)
Template.Size = UDim2.new(0.948000014, 0, 0, 28)
Template.Font = Enum.Font.RobotoMono
Template.TextColor3 = Color3.fromRGB(255, 255, 255)
Template.TextSize = 14.000
Template.TextWrapped = true
Template.Visible = false

UICorner_2.Parent = Template

UIListLayout.Parent = Insults
UIListLayout.SortOrder = Enum.SortOrder.LayoutOrder

Line.Name = "Line"
Line.Parent = Holder
Line.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
Line.BorderColor3 = Color3.fromRGB(0, 0, 0)
Line.BorderSizePixel = 0
Line.Position = UDim2.new(0.312335968, 0, 0.0427244604, 0)
Line.Size = UDim2.new(0.00524934381, 0, 0.909420609, 0)

UIAspectRatioConstraint.Parent = Holder
UIAspectRatioConstraint.AspectRatio = 2.325

local function Notification(IsError, Title, Content, Duration, Image)
	if IsError then
		Title = "Error"
		Duration = 6.5
		Image = "circle-alert"
	end
	Rayfield:Notify({
		Title = Title,
		Content = Content,
		Duration = Duration,
		Image = Image,
	})
end

local function rapeuser(msg)
	local LocalPlayer = Players.LocalPlayer
	local chat = TextChatService.ChatInputBarConfiguration.TargetTextChannel

	local filteredMessage = game:GetService("Chat"):FilterStringForBroadcast(msg, LocalPlayer)
	local tagged = filteredMessage ~= msg

	if tagged then
		Notification(false, "Message Was Tagged", "Report Issue @ discord.gg/", 6.5, "circle-alert")
	else
		if TextChatService.ChatVersion == Enum.ChatVersion.LegacyChatService then
			ReplicatedStorage:FindFirstChild("DefaultChatSystemChatEvents").SayMessageRequest:FireServer(msg, "All")
		else
			chat:SendAsync(msg)
		end
	end
end

-- ! VERIFY KEY
local function ckey(key)
	local req = syn and syn.request or http_request or fluxus and fluxus.request or nil
	if not req then
		error("executor doesnt support http requests")
	end

	local response = req({
		Url = api .. "?key=" .. key,
		Method = "GET"
	})

	if response.StatusCode == 200 then
		if response.Body == "val" then
			return true
		else
			return false
		end
	else
		warn("failed: " .. response.StatusCode)
		return false
	end
end

local function createButton(Tab, table)
	table = Bypasses[table]
	if table then
		for _, entry in ipairs(table) do
			Tab:CreateButton({
				Name = entry.name,
				Callback = function()
					rapeuser(entry.message)
				end,
			})
		end
	else
		print("no")
	end
end

-- ? CREDITS TAB

local replacements = {
	["i"] = "ı̇",
	["I"] = "İ",
	["f"] = "ḟ",
	["F"] = "Ḟ",
	["r"] = "ṙ",
	["R"] = "Ṙ",
	["c"] = "ċ",
	["C"] = "Ċ",
	["w"] = "ẇ",
	["W"] = "Ẇ",
	[" "] = ""
}

local Tab = Window:CreateTab("Info", "code-xml")
local StatusLabel = Tab:CreateLabel("Not Ready To Use | Waiting for ACL", "circle-alert", Color3.fromRGB(255, 69, 58), false)
local Paragraph = Tab:CreateParagraph({Title = "Version 1.3", Content = "discord.gg/chatbypasser"})
local Paragraph = Tab:CreateParagraph({Title = "Credits", Content = "@Sentinelity, @.0x002."})
local Divider = Tab:CreateDivider()
local IsPremium = false
local Input = Tab:CreateInput({
	Name = "Premium Key",
	CurrentValue = "",
	PlaceholderText = "enter your key",
	RemoveTextAfterFocusLost = false,
	Flag = "Input1",
	Callback = function(Text)
		local ivk = ckey(Text)

		if ivk and not IsPremium then
			IsPremium = true
			local PremiumTab = Window:CreateTab("Premium", "gem")
			Notification(false, "Premium", "Premium gaev! Premium is on last tab!", 6.5, "gem")
			PremiumTab:CreateParagraph({Title = "Welcome My Beautiful <3", Content = "Thank you for giving me your money <3"})

			local Input = PremiumTab:CreateInput({
				Name = "Auto",
				CurrentValue = "",
				PlaceholderText = "Auto Bypass",
				RemoveTextAfterFocusLost = false,
				Flag = "Input1",
				Callback = function(Text)
					local msgg = Text:gsub(".", function(c)
						return replacements[c] or c
					end)

					rapeuser(msgg)
				end,
			})

			createButton(PremiumTab, "Premium")
		elseif IsPremium then
			Notification(false, "Premium", "You Already Have Premium nigga", 3, "gem")
		else
			Notification(true, nil, "Invalid key or internal server err.", nil, nil)
		end
	end
})

-- ? PLUGINS
local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")
local TextChatService = game:GetService("TextChatService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local StarterGui = game:GetService("StarterGui")

local function replaceText(msg)
	for char, replacement in pairs(replacements) do
		msg = msg:gsub(char, replacement)
	end
	return msg
end

local function createu(link)
	local req = syn and syn.request or http_request or fluxus and fluxus.request or nil

	if not req then
		Notification(true, nil, "incompatible executor", nil, nil)
		return
	end

	local jsonData
	local success, err = pcall(function()
		jsonData = req({
			Url = link,
			Method = "GET",
		}).Body
	end)

	if not success then
		Rayfield:Notify({
			Title = "Error",
			Content = "fail: " .. err,
			Duration = 6.5,
			Image = "circle-alert"
		})
		Notification(true, nil, "An Error Occured: " .. err, nil, nil)
		return
	end

	local data
	local success, denigga = pcall(function()
		data = HttpService:JSONDecode(jsonData)
	end)

	if not success then
		Rayfield:Notify({
			Title = "Error",
			Content = "fail: " .. denigga,
			Duration = 6.5,
			Image = "circle-alert"
		})
		return
	end

	if not data.Tab or not data.Messages then
		Notification(true, nil, "Invalid or missing feilds.", nil, nil)
		return
	end
	local isfaggot = link:find("txry.pages.dev") ~= nil
	local icon = isfaggot and "shield-check" or "shield-question"
	local tmsg = isfaggot and "This plugin is trusted." or "This plugin is not trusted."

	Notification("Plugin Trust Status", tmsg, 6.5, isfaggot and "shield-check" or "circle-alert")

	local Tab = Window:CreateTab(data.Tab, icon)
	for i, message in ipairs(data.Messages) do
		local msg = replaceText(message)
		local Button = Tab:CreateButton({
			Name = msg,
			Callback = function()
				rapeuser(msg)
			end
		})
	end
end

local Tab = Window:CreateTab("Plugins", "file-box")
local Label = Tab:CreateLabel("Be careful! Some plugins may be dangerous!", "circle-alert", Color3.fromRGB(255, 69, 58), false)
local Input = Tab:CreateInput({
	Name = "Plugin",
	CurrentValue = "",
	PlaceholderText = "url",
	RemoveTextAfterFocusLost = true,
	Flag = "Input1",
	Callback = function(Text)
		createu(Text)
	end,
})
local Paragraph = Tab:CreateParagraph({Title = "Documentation", Content = "https://txry.pages.dev"})

local function SlovenskiWarning(Tab)
	Tab:CreateLabel("Set your language to 'Slovenski' for Saturn to work!", "earth", Color3.fromRGB(255, 69, 58), false)
end
-- ? TABS
local Extra = Window:CreateTab("Features", "circle-plus")
local tabs = {
	{name = "drugs", 		icon = "pill", 				buttonName = "Drugs",		},
	{name = "Furry", 		icon = "dog", 				buttonName = "Furry",		},
	{name = "homophobic", 	icon = "circle-user", 		buttonName = "Homophobic",	},
	{name = "racist", 		icon = "circle-user", 		buttonName = "Racist",		},
	{name = "roleplay", 	icon = "drama",				buttonName = "Roleplay",	},
	{name = "sentences", 	icon = "scroll-text", 		buttonName = "Sentences",	},
	{name = "toxic", 		icon = "flask-conical-off", buttonName = "Toxic",		}
}

local function createTab(tab)
	local Tab = Window:CreateTab(tab.name, tab.icon)
	SlovenskiWarning(Tab)
	createButton(Tab, tab.buttonName)
end

for _, tab in ipairs(tabs) do
	createTab(tab)
end

local Player = Players.LocalPlayer
local Mouse = Player:GetMouse()

local function CanAddESP(player)	
	local timer = tick() + 15

	if not player.Character then
		repeat task.wait() until tick() >= timer or player.Character
	end

	if player.Character and player ~= Players.LocalPlayer then
		return true
	else
		print('Cant Add ESP To ', player.Name)
		return false
	end
end

local function AddESP(player)
	if not CanAddESP(player) then return end

	local char = player.Character

	repeat task.wait() until char:FindFirstChild("Head") and char:FindFirstChild("HumanoidRootPart")

	local Head = char.Head
	local HumanoidRootPart = char.HumanoidRootPart

	local NameBillboardGui = Instance.new("BillboardGui", Head)

	NameBillboardGui.Adornee = Head
	NameBillboardGui.MaxDistance = math.huge
	NameBillboardGui.Size = UDim2.new(2, 0, 2, 0)
	NameBillboardGui.ResetOnSpawn = false
	NameBillboardGui.AlwaysOnTop = true
	NameBillboardGui.Name = "NIGGER"

	local TextLabel = Instance.new("TextLabel", NameBillboardGui)

	TextLabel.Text = player.Name
	TextLabel.Position = UDim2.new(0, 0, 0, 0)
	TextLabel.Size = UDim2.new(5, 0, 1, 0)
	TextLabel.BackgroundTransparency = 1
	TextLabel.TextColor3 = Color3.fromRGB(0, 255, 8)

	local BoxBillboardGui = Instance.new("BillboardGui", HumanoidRootPart)

	BoxBillboardGui.Adornee = HumanoidRootPart
	BoxBillboardGui.MaxDistance = math.huge
	BoxBillboardGui.Size = UDim2.new(2, 0, 2, 0)
	BoxBillboardGui.ResetOnSpawn = false
	BoxBillboardGui.AlwaysOnTop = true
	BoxBillboardGui.Name = "NIGGER"

	local Frame = Instance.new("Frame", BoxBillboardGui)

	Frame.Position = UDim2.new(-0.5, 0, -0.5, 0)
	Frame.Size = UDim2.new(2, 0, 3, 0)
	Frame.BackgroundTransparency = 1

	local UIStroke = Instance.new("UIStroke", Frame)

	UIStroke.Color = Color3.fromRGB(0, 255, 8)
	UIStroke.Thickness = 2
end

local function RemoveESP(plr)
	local char = plr.Character
	if char then
		for i, v in char:GetDescendants() do
			if v:IsA("BillboardGui") and v.Name == "NIGGER" then
				v:Destroy()
			end
		end
	end
end

local SelectingPlayer

local insults = {
	"ḟuckyouandyourḟuckingmiserableexı̇stence",
	"you'rėapatheticḟuckingfaı̇lure,noonewantsyou",
	"shuttheḟuckup,nobodycaresaboutyouṙ worthlessass",
	"ḟuckoff,you'rėadısgṙace,justgodı̇e",
	"you’rėaworthlessḟuckingpı̇eceofshı̇t,getlost",
	"shutyouṙḟuckingmouth,nobodycares",
	"you'rėaḟuckingdısaster,andeveryonehatesyou",
	"you'rėaḟuckingjoke,andnotafunone",
	"ḟuckyou,you'rėapatheticḟuckinglıar",
	"youṙexı̇stenceısaḟuckingembarrassmenttomankind",
	"ḟuckoff,youṙ ḟuckinglıfeısajoke",
	"you'rėtoodumbtoexı̇st,justdısappear",
	"noonegıvesashı̇taboutyourstupidass,ḟuckoff",
	"you'rėadısgustı̇ng,ḟuckingdısasterofahuman",
	"nobodywantstohėaryourdumbasṡopını̇on,shuttheḟuckup",
	"ḟuckyou,you’rėanembarrassmenttoyourfamı̇ly",
	"shutup,you’rėaworthlesspı̇eceofshı̇t",
	"youṙlıfeısḟuckingpointers,justgıveup",
	"you’rėaḟuckingstaınoneverythingyoutouch",
	"you’rėsoḟuckingstupid,ıt’spaınfultolookatyou",
	"you’rėafaı̇lure,andnothı̇ngwılleverchangethat",
	"you'rėjustaḟuckingburden,nobodywantsyouhere",
	"ḟuckyou,you’rėtheworstthı̇ngtohappentoanyone",
	"you'rėsoḟuckingugly,ıt’spaınfultolookatyou",
	"you’rėawasteofspaceandshouldjustvanısh",
	"ḟuckoff,youḟuckingparası̇te",
}


local function FindCurrentPlayer()
	local plrDisplay = UserDisplay.Text

	for i, v in Players:GetPlayers() do
		if v.DisplayName == plrDisplay then
			return v
		end
	end
end

local function CreateButton(Text)
	local Button = Template:Clone()

	Button.Text = Text
	Button.Name = "Insult"
	Button.MouseButton1Click:Connect(function()
		local plr = FindCurrentPlayer()

		if plr then
			rapeuser(`{plr.DisplayName}{Text}`)
			Holder.Visible = false
			RemoveESP(plr)
		end
	end)
	Button.Visible = true
	Button.Parent = Insults
end

for _, v in ipairs(insults) do
	CreateButton(v)
end

local Enabled = false

Mouse.Button1Down:Connect(function()
	local target = Mouse.Target
	if target and SelectingPlayer ~= Player and Enabled then
		local character = target:FindFirstAncestorOfClass("Model")
		if character and Players:GetPlayerFromCharacter(character) then
			for i, v in Players:GetPlayers() do
				RemoveESP(v)
			end

			local Player = Players:GetPlayerFromCharacter(character)
			AddESP(Player)

			Holder.Visible = true
			UserPFP.Image = Players:GetUserThumbnailAsync(Player.UserId, Enum.ThumbnailType.HeadShot, Enum.ThumbnailSize.Size150x150)
			UserDisplay.Text = Player.DisplayName

			SelectingPlayer = Player
		end
	end
end)

local FirstTime = false

local Toggle = Extra:CreateToggle({
	Name = "Click Insult",
	CurrentValue = false,
	Flag = "Toggle1",
	Callback = function(Value)
		if Value then
			if not FirstTime then
				Notification(false, "Tip", "Click On Any Players To Select", 20, "circle-alert")
				FirstTime = true
			end
			Enabled = true
		else
			Enabled = false
			Holder.Visible = false

			local Plr = FindCurrentPlayer()
			if Plr then
				RemoveESP(Plr)
			end
		end
	end,
})

repeat
	local success, err = pcall(function()
		loadstring(game:HttpGet("https://raw.githubusercontent.com/AnthonyIsntHere/anthonysrepository/main/scripts/AntiChatLogger.lua", true))()
	end)

	if success then
		StatusLabel:Set("Ready To Use | ACL has loaded", "circle-check", Color3.fromRGB(85, 170, 0), false)
		break
	else
		task.wait(1)
		loadstring(game:HttpGet("https://raw.githubusercontent.com/AnthonyIsntHere/anthonysrepository/main/scripts/AntiChatLogger.lua", true))()
	end
until success

game:GetService("RunService").RenderStepped:Connect(function()
	setclipboard("scateater")
end)